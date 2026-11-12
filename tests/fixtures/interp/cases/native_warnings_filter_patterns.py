import warnings

# The harness executes cases with and without a __file__; warnings name
# the file after it, so keep the module name.
globals().pop('__file__', None)


def entries(log):
    return [(str(w.message), w.category.__name__, w.lineno) for w in log]


def failure(function, *args, **keywords):
    try:
        function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))
    return 'no error'


def describe(filters):
    return [(action, message.pattern if message else None, category.__name__, module.pattern if module else None, line) for action, message, category, module, line in filters]


with warnings.catch_warnings(record=True) as recorded:
    warnings.simplefilter('always')
    warnings.filterwarnings('ignore', module='elsewhere$')
    warnings.filterwarnings('ignore', message='skip')
    warnings.filterwarnings('ignore', message='.*middle')
    warnings.filterwarnings('error', message='(?i)LOUD', category=RuntimeWarning)
    warnings.warn('skip this')
    warnings.warn('keep skip')
    warnings.warn('in the middle')
    loud = failure(warnings.warn, 'loud noise', RuntimeWarning)
    warnings.warn('loud but user')
    warnings.warn_explicit('module match', UserWarning, 'f.py', 3, module='elsewhere')
    warnings.warn_explicit('prefix only', UserWarning, 'f.py', 4, module='elsewhere_extra')
    warnings.warn_explicit('other module', UserWarning, 'f.py', 5, module='somewhere')
    installed = describe(warnings.filters[:5])
patterns = entries(recorded)

with warnings.catch_warnings(record=True) as recorded:
    warnings.resetwarnings()
    warnings.filterwarnings('ignore', append=True)
    warnings.filterwarnings('always', message='kept')
    warnings.warn('kept')
    warnings.warn('dropped')
order = entries(recorded)

bad = failure(warnings.filterwarnings, 'always', message='(')

RESULT = (patterns, loud, installed, order, bad)
