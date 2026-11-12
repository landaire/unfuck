def K(x):
    return x

def call(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)

def reduced(exception):
    # Builtin classes are named rather than shown, since their repr is not
    # what this case checks.
    parts = exception.__reduce__()
    return (parts[0].__name__,) + parts[1:]

def environment():
    rows = []
    e = IOError(K(1), K('x'), K('f'))
    rows.append((e.args, e.errno, e.strerror, e.filename, str(e), repr(e)))
    rows.append(reduced(e))
    rows.append((reduced(IOError(K(1), K('x'))), reduced(IOError(K('a'))), reduced(OSError())))
    e.foo = K(1)
    rows.append(reduced(e))
    del e.errno
    rows.append((e.errno, str(e)))
    del e.errno
    e.filename = None
    rows.append(str(e))
    del e.filename
    rows.append((str(e), e.filename))
    e.errno = K(7)
    rows.append(str(e))
    e.args = (K(5),)
    rows.append((str(e), e.errno, e.strerror))
    plain = EnvironmentError(K('only'))
    rows.append((str(plain), plain.errno, plain.strerror, plain.filename, plain.__dict__))
    plain.strerror = K('s')
    plain.errno = K(3)
    rows.append(str(plain))
    many = IOError(K(1), K(2), K(3), K(4))
    rows.append((str(many), many.errno, many.args))
    rows.append((str(IOError()), str(OSError(K(2), K('x'))), str(IOError(K(1), K(u'u')))))
    rows.append((repr(EnvironmentError.errno), type(IOError.__dict__.get('errno')).__name__))
    rows.append(sorted(name for name in EnvironmentError.__dict__ if name not in ('__new__', '__doc__')))
    rows.append(call(EnvironmentError.errno.__get__, K(1)))
    rows.append(call(IOError(K(1), K('x')).__reduce__, K(2)))
    rows.append(IOError(K(1), K('x'), K('f')).__dict__)
    again = IOError(K(1), K('x'))
    again.__init__(K('y'))
    rows.append((again.args, again.errno, again.strerror, str(again)))
    return rows

def windows():
    rows = []
    w = WindowsError(K(5), K('denied'))
    rows.append((w.args, w.errno, w.winerror, w.strerror, str(w), repr(w), reduced(w)))
    w = WindowsError(K(3), K('nf'), K('p'))
    rows.append((w.args, w.errno, w.winerror, w.filename, str(w), reduced(w)))
    rows.append((call(WindowsError, K('x'), K('y')), str(WindowsError(K(2.7), K('y'))), WindowsError(K(2.7), K('y')).errno))
    rows.append([WindowsError(K(code), K('m')).errno for code in [2, 4, 6, 10, 17, 32, 109, 112, 145, 183, 200, 215, 1816, 99999, -1, True, 5L]])
    rows.append((str(WindowsError(K(1))), WindowsError(K(1)).winerror, str(WindowsError()), WindowsError(K(1), K(2), K(3), K(4)).winerror))
    w = WindowsError(K(5), K('d'))
    w.winerror = None
    rows.append(str(w))
    del w.winerror
    rows.append(str(w))
    rows.append(repr(WindowsError.winerror))
    rows.append(sorted(name for name in WindowsError.__dict__ if name not in ('__new__', '__doc__')))
    return rows

RESULT = [
    environment(),
    windows(),
]
