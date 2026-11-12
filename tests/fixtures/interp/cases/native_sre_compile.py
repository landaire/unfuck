import _sre

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

code = [17, 10, 3, 2, 2, 2, 2, 97, 98, 0, 0, 19, 97, 19, 98, 1]
pattern = _sre.compile('ab', 3, code, 2, {'x': 1}, [None, 'x'])
plain = _sre.compile(u'ab', 0, code)

def assign():
    pattern.flags = 1

def delete():
    del pattern.pattern

errors = [
    attempt(_sre.compile, 'a'),
    attempt(_sre.compile, 'a', 0, ()),
    attempt(_sre.compile, 'a', 'x', code),
    attempt(_sre.compile, 'a', 0, code, 1, 2, 3, 4),
    attempt(_sre.compile, 'a', 0, [2 ** 32]),
    attempt(_sre.compile, 'a', 0, [-1]),
    attempt(_sre.compile, 'a', 0, code, 1.5),
    attempt(assign),
    attempt(delete),
    attempt(type(pattern)),
    attempt(pattern.__copy__),
    attempt(pattern.__deepcopy__, {}),
]
RESULT = (pattern.pattern, pattern.flags, pattern.groups, pattern.groupindex, plain.pattern, plain.groupindex,
          plain.groups, type(pattern) is type(plain), repr(type(pattern)), type(pattern).__name__,
          type(pattern).__module__, repr(type(pattern).pattern), errors,
          sorted(name for name in dir(pattern) if name[:1] != '_'))
