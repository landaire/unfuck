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
registry = {}
results = [
    attempt(_warnings.warn_explicit, 'm', DeprecationWarning, 'f.py', 3, None, registry),
    attempt(_warnings.warn_explicit, 'm', UserWarning, 'f.py', 'x'),
    attempt(_warnings.warn_explicit, 'm', 5, 'f.py', 1),
    attempt(_warnings.warn_explicit, 'm', UserWarning, 'f.py', 1, None, 1),
    attempt(_warnings.warn_explicit, 'm', UserWarning),
]
ignored_key = ('m', DeprecationWarning, 3) in registry

_warnings.filters[0:0] = [('error', None, UserWarning, Exact('mymod'), 0)]
results = results + [attempt(_warnings.warn_explicit, 'module match', UserWarning, 'mymod.py', 1)]
results = results + [attempt(_warnings.warn_explicit, 'given module', UserWarning, 'other.py', 1, 'mymod')]
del _warnings.filters[0]

_warnings.filters[0:0] = [('error', None, UserWarning, None, 7)]
results = results + [attempt(_warnings.warn_explicit, 'line match', UserWarning, 'x.py', 7)]
seen = {('already', UserWarning, 7): True}
results = results + [attempt(_warnings.warn_explicit, 'already', UserWarning, 'x.py', 7, None, seen)]
del _warnings.filters[0]

_warnings.filters[0:0] = [('once', None, FutureWarning, None, 0)]
once = {}
results = results + [attempt(_warnings.warn_explicit, 'fw', FutureWarning, 'f.py', 3, None, once)]
results = results + [attempt(_warnings.warn_explicit, 'global once', FutureWarning, 'f.py', 3)]
global_once = ('global once', FutureWarning) in _warnings.once_registry
del _warnings.once_registry[('global once', FutureWarning)]
del _warnings.filters[0]

_warnings.filters[0:0] = [('module', None, BytesWarning, None, 0)]
module_registry = {}
results = results + [attempt(_warnings.warn_explicit, 'mod', BytesWarning, 'f.py', 4, None, module_registry)]
del _warnings.filters[0]

_warnings.filters[0:0] = [('error', None, ImportWarning, None, 0)]
results = results + [attempt(_warnings.warn_explicit, ImportWarning('inst'), UserWarning, 'f.py', 4)]
del _warnings.filters[0]

_warnings.filters[:] = saved
RESULT = (results, ignored_key, ('fw', FutureWarning, 3) in once, ('fw', FutureWarning) in once, global_once,
          ('mod', BytesWarning) in module_registry, ('mod', BytesWarning, 4) in module_registry,
          len(registry), len(once), len(module_registry), len(_warnings.once_registry))
