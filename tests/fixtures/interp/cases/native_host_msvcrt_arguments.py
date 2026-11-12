def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except BaseException as e:
        return (type(e).__name__, e.args)

def windows():
    import msvcrt as m
    names = sorted(name for name in dir(m) if not name.startswith('__'))
    constants = [(name, getattr(m, name)) for name in names if name.isupper()]
    arguments = [
        attempt(m.heapmin, K(1)), attempt(m.kbhit, K(1)), attempt(m.getch, K(1)), attempt(m.getwch, K(1)),
        attempt(m.getche, K(1)), attempt(m.getwche, K(1)), attempt(m.kbhit, a=K(1)),
        attempt(m.locking, K(1), K(2)), attempt(m.locking, K('a'), K(2), K(3)), attempt(m.locking, K(1), K(2), K(2 ** 64)),
        attempt(m.locking, K(1), K(2), K(2.5)), attempt(m.locking, K(1), K(2 ** 64), K(1)),
        attempt(m.setmode, K(1)), attempt(m.setmode, K(1.5), K(2)), attempt(m.setmode, K(1), None),
        attempt(m.open_osfhandle, K(1)), attempt(m.open_osfhandle, K(2 ** 64), K(0)), attempt(m.open_osfhandle, K(-2 ** 64), K(0)),
        attempt(m.open_osfhandle, K('a'), K(0)),
        attempt(m.get_osfhandle, K(-1)), attempt(m.get_osfhandle, K(5000)), attempt(m.get_osfhandle, K(2048)),
        attempt(m.get_osfhandle, K(-2)), attempt(m.get_osfhandle, K('x')), attempt(m.get_osfhandle),
        attempt(m.putch, K('ab')), attempt(m.putch, K(u'a')), attempt(m.putch, K(1)), attempt(m.putch),
        attempt(m.putch, bytearray(K('a'))), attempt(m.putch, None),
        attempt(m.ungetch, K('ab')), attempt(m.ungetch, K(5)),
        attempt(m.putwch, K('a')), attempt(m.putwch, K(u'')), attempt(m.putwch, K(5)), attempt(m.putwch, bytearray(K('a'))),
        attempt(m.putwch, None),
        attempt(m.ungetwch, K('a')), attempt(m.ungetwch, K(5)), attempt(m.ungetwch, None),
    ]
    return [names, constants, arguments, m.__doc__]

RESULT = windows()
