import warnings

# The harness executes cases with and without a __file__; warnings name
# the file after it, so keep the module name.
globals().pop('__file__', None)


def failure(function, *args, **keywords):
    try:
        function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))
    return 'no error'


def entries(log):
    return [(str(w.message), w.category.__name__, w.filename, w.lineno) for w in log]


def emit(text, category=UserWarning, level=1):
    warnings.warn(text, category, stacklevel=level)


def caller():
    emit('from caller', level=2)


with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('always')
    emit('first')
    emit('second', RuntimeWarning)
    caller()
    warnings.warn_explicit('explicit', UserWarning, 'somefile.py', 42)
    warnings.warn_explicit('with module', UserWarning, 'other.py', 7, module='mod.name')
always = entries(recorded)

with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('default')
    for repeat in range(3):
        emit('repeated')
    for repeat in range(2):
        warnings.warn('same line')
        warnings.warn('same line')
default = entries(recorded)
registry_keys = sorted((key[0], key[1].__name__, key[2]) for key in __warningregistry__ if len(key) == 3)

with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('once')
    emit('once a')
    emit('once a')
    warnings.warn('once a')
once = entries(recorded)

with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('always')
    warnings.simplefilter('ignore', RuntimeWarning)
    warnings.simplefilter('error', UserWarning, lineno=emit.func_code.co_firstlineno + 1)
    emit('ignored by category', RuntimeWarning)
    line_filtered = failure(emit, 'line filter')
    warnings.warn('other line')
module_filtered = entries(recorded)

shown = []


def custom(message, category, filename, lineno, file=None, line=None):
    shown.append((str(message), category.__name__, filename, lineno))


with warnings.catch_warnings():
    warnings.simplefilter('always')
    warnings.showwarning = custom
    warnings.warn('to custom')
    warnings.showwarning = len
    builtin_hook = failure(warnings.warn, 'to builtin')
    del warnings.showwarning
    removed = failure(warnings.warn, 'to stderr')

with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('error')
    as_error = failure(warnings.warn, 'boom', DeprecationWarning)
    explicit_error = failure(warnings.warn_explicit, 'bang', SyntaxWarning, 'f.py', 3)

RESULT = (always, default, registry_keys, once, line_filtered, module_filtered, shown, builtin_hook, removed, as_error, explicit_error, recorded)

import linecache

looked_up = []
stock_getline = linecache.getline


def fake_getline(filename, lineno, module_globals=None):
    looked_up.append((filename, lineno))
    return ''


formatted = []
stock_format = warnings.formatwarning


def counting_format(message, category, filename, lineno, line=None):
    formatted.append(str(message))
    return ''


class Loader(object):
    @property
    def get_source(self):
        raise RuntimeError('boom')


with warnings.catch_warnings():
    warnings.simplefilter('always')
    linecache.getline = fake_getline
    try:
        warnings.warn_explicit('via linecache', UserWarning, 'f.py', 3)
    finally:
        linecache.getline = stock_getline
    warnings.formatwarning = counting_format
    try:
        warnings.warn('via format')
    finally:
        warnings.formatwarning = stock_format
    warnings.warn('stock display')
    warnings.showwarning = custom
    warnings.warn_explicit('loader probe', UserWarning, 'g.py', 1, module_globals={'__loader__': Loader(), '__name__': 'g'})

RESULT = RESULT + (looked_up, formatted, shown[-1])
