import copy

def K(x):
    return x

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

def reduced(e):
    parts = e.__reduce__()
    return (parts[0].__name__,) + parts[1:]

fresh = ValueError(K(1), K('two'))
stored = ValueError(K(1))
stored.extra = K(3)
touched = ValueError(K(1))
touched.__dict__
deleted = ValueError(K(1))
missing = attempt(delattr, deleted, 'nothing')
io = IOError(K(2), K('No such file'), K('name'))
reductions = [reduced(fresh), reduced(stored), reduced(touched), reduced(deleted), missing, reduced(io), reduced(KeyError())]

state = ValueError(K(5))
setstates = [
    state.__setstate__(None),
    reduced(state),
    state.__setstate__({'a': K(1)}),
    reduced(state),
    state.a,
    attempt(state.__setstate__, K([])),
    attempt(state.__setstate__, {K(1): 2}),
    attempt(state.__setstate__),
    attempt(BaseException.__setstate__, K(3), {}),
    attempt(BaseException.__reduce__, K(3)),
    attempt(fresh.__reduce__, K(1)),
]

class Loud(Exception):
    def __str__(self):
        return u'loud \xe9'

unicodes = [
    unicode(Exception()),
    unicode(Exception(K('a'))),
    unicode(Exception(K(u'\xe9'))),
    unicode(Exception(K(1), K(2))),
    unicode(KeyError(K('k'))),
    unicode(IOError(K(1), K('m'))),
    unicode(IOError(K(1), K('m'), K('f'))),
    unicode(Loud(K(1))),
    Exception(K(u'x')).__unicode__(),
    KeyError(K(u'k')).__unicode__(),
    attempt(BaseException.__unicode__, K(1)),
    attempt(Exception().__unicode__, K(1)),
]

# Windows takes the base name after a backslash.
syntax = SyntaxError(K('bad'), (K('f.py'), K(3), K(4), K('text')))
syntax_state = [
    syntax.msg, syntax.filename, syntax.lineno, syntax.offset, syntax.text, syntax.print_file_and_line,
    str(syntax), reduced(syntax), syntax.__dict__, reduced(syntax),
    type(SyntaxError.__dict__['msg']).__name__,
    attempt(SyntaxError, K('m'), K((1, 2))),
    str(SyntaxError()), SyntaxError(K('m')).filename,
    str(SyntaxError(K('bad'), (K('a\\b\\f.py'), 3, 4, 't'))), str(SyntaxError(K('bad'), (K('a/b/f.py'), 3, 4, 't'))),
]
syntax.lineno = K('x')
syntax_state.append(str(syntax))

copied = copy.copy(stored)
copies = [type(copied).__name__, copied.args, copied.extra, copied is stored]

import _ssl
ssl_error = _ssl.SSLError(K(1), K(u'm\xe9'))
slots = [
    unicode(ssl_error), ssl_error.__unicode__(), attempt(str, ssl_error), attempt(str, _ssl.SSLError(K(1), K(2))),
    unicode(_ssl.SSLError(K(1), K(2))),
    attempt(str, _ssl.SSLError(K(1), K(2), K(3))),
    # Only the type: these messages name the receiver's `tp_name`.
    attempt(SyntaxError.filename.__get__, IOError(K(1), K('m'), K('f')))[0],
    attempt(SyntaxError.msg.__get__, ValueError())[0],
    attempt(BaseException.__reduce__, K(3), K(1)),
    attempt(BaseException.__setstate__, K(3)),
    attempt(BaseException.__unicode__, K(3), K(1)),
    attempt(EnvironmentError.__reduce__, ValueError())[0],
    attempt(BaseException.__reduce__),
]

RESULT = (reductions, setstates, unicodes, syntax_state, copies, slots)
