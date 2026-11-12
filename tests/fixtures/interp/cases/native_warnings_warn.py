import _warnings

def attempt(function, *args, **keywords):
    try:
        return ('returned', function(*args, **keywords))
    except Exception as e:
        return (type(e).__name__, e.args)

class Exact(object):
    def __init__(self, text):
        self.text = text

    def match(self, subject):
        return subject == self.text

saved = _warnings.filters[:]
defaults = [(entry[0], entry[1], entry[2].__name__, entry[3], entry[4]) for entry in _warnings.filters]
classes = [entry[2] for entry in _warnings.filters] == [DeprecationWarning, PendingDeprecationWarning, ImportWarning, BytesWarning]
results = [
    attempt(_warnings.warn),
    attempt(_warnings.warn, 'x', None),
    attempt(_warnings.warn, 'x', int),
    attempt(_warnings.warn, 'x', 1),
    attempt(_warnings.warn, 'x', UserWarning, 'a'),
    attempt(_warnings.warn, 'x', UserWarning, 1.5),
    attempt(_warnings.warn, 'x', DeprecationWarning),
    attempt(_warnings.warn, DeprecationWarning('y')),
    attempt(_warnings.warn, 'x', PendingDeprecationWarning, stacklevel=3),
    attempt(_warnings.warn, 'x', category=ImportWarning),
]

_warnings.filters[0:0] = [('error', None, RuntimeWarning, None, 0)]
results = results + [attempt(_warnings.warn, 'boom', RuntimeWarning)]
results = results + [attempt(_warnings.warn, RuntimeWarning('instance', 2))]
results = results + [attempt(_warnings.warn, 'boom', RuntimeWarning, 4)]

_warnings.filters[0:0] = [('error', Exact('exact text'), UnicodeWarning, None, 0)]
results = results + [attempt(_warnings.warn, 'exact text', UnicodeWarning)]

_warnings.filters[0:0] = [('error', None, FutureWarning, Exact(__name__), 0)]
results = results + [attempt(_warnings.warn, 'here', FutureWarning)]

class OddWarning(SyntaxWarning):
    pass

_warnings.filters[0:0] = [('bogus', None, OddWarning, None, 0)]
results = results + [attempt(_warnings.warn, 'b', OddWarning)]

_warnings.filters[0:0] = [5]
results = results + [attempt(_warnings.warn, 'c', SyntaxWarning)]

_warnings.filters[:] = saved
RESULT = (defaults, classes, _warnings.default_action, _warnings.once_registry, results, len(_warnings.filters))
