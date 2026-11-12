FIELDS = ('msg', 'filename', 'lineno', 'offset', 'text', 'print_file_and_line')


def describe(error):
    return (type(error).__name__, error.args, str(error)) + tuple(getattr(error, name) for name in FIELDS)


def outcome(action):
    try:
        return describe(action())
    except Exception as error:
        return type(error).__name__, str(error)


class Custom(SyntaxError):
    pass


located = SyntaxError('message')
located.lineno = 7
located.filename = 'located.py'

RESULT = [
    outcome(lambda: SyntaxError('invalid syntax', ('file.py', 3, 5, 'x y\n'))),
    outcome(lambda: SyntaxError('message')),
    outcome(lambda: SyntaxError()),
    outcome(lambda: SyntaxError('a', 'b', 'c')),
    outcome(lambda: SyntaxError('message', ['list.py', 2, None, None])),
    outcome(lambda: SyntaxError('message', (None, 2, None, None))),
    outcome(lambda: SyntaxError('message', ('name.py', None, None, None))),
    outcome(lambda: SyntaxError('message', ('name.py', True, None, None))),
    outcome(lambda: SyntaxError('message', ('name.py', 2L, None, None))),
    outcome(lambda: SyntaxError(3, ('name.py', 2, None, None))),
    outcome(lambda: SyntaxError(u'unicode', ('name.py', 2, None, None))),
    outcome(lambda: SyntaxError('message', (1, 2))),
    outcome(lambda: SyntaxError('message', 5)),
    outcome(lambda: IndentationError('expected an indented block', ('<string>', 2, 1, 'x\n'))),
    outcome(lambda: TabError('inconsistent', ('<string>', 4, 3, '\tx\n'))),
    outcome(lambda: Custom('custom', ('custom.py', 9, 1, None))),
    describe(located),
]
