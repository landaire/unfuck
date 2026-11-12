FIELDS = ('msg', 'filename', 'lineno', 'offset', 'text')


def failure(source, mode='exec'):
    try:
        compile(source, 'broken.py', mode)
    except SyntaxError as error:
        return (type(error).__name__, error.args, str(error)) + tuple(getattr(error, name) for name in FIELDS)
    return 'compiled'


def exec_failure(source):
    try:
        exec source in {}
    except SyntaxError as error:
        return (type(error).__name__, error.args, str(error)) + tuple(getattr(error, name) for name in FIELDS)
    return 'ran'


RESULT = [
    failure('x y'),
    failure('if x:\npass'),
    failure('if x:\n        a\n\tb'),
    failure('1 = x'),
    failure('return 1'),
    failure('break'),
    failure('def f(a, a):\n    pass'),
    failure('def f(x):\n    global x'),
    failure('def f():\n    from os import *\n    def g():\n        return path'),
    failure('def f():\n    x = 1\n    def g():\n        return x\n    del x'),
    failure('x +', 'eval'),
    exec_failure('yield 1'),
    exec_failure('class C:\n    return 2'),
]
