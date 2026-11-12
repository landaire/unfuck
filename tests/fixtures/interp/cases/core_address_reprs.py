import re
import sys
import weakref

def K(value):
    return value

def norm(value):
    return re.sub(r'0x[0-9a-fA-F]+|\b[0-9A-F]{16}\b', 'ADDR', value)

class New(object):
    pass

class Classic:
    pass

def function():
    pass

def generator():
    yield K(1)

exec('def ' + 'g' * 250 + '():\n    yield 1\n')
long_generator = globals()['g' * 250]

def cells():
    def inner():
        return value
    empty = repr(inner.func_closure[0])
    value = K(5)
    return empty, repr(inner.func_closure[0])

new = New()
reference = weakref.ref(new)
dead = weakref.ref(New())
proxy = weakref.proxy(new)

RESULT = [
    norm(repr(value)) for value in [
        function, Classic, Classic(), new, object(), generator(), long_generator(),
        memoryview(K('ab')), reference, dead, proxy, weakref.ref(function), sys.stdout,
    ]
] + [norm(text) for text in cells()]
