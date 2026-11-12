import imp

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

suffixes = [entry for entry in imp.get_suffixes() if entry[0] in ('.py', '.pyc')]
builtin = [imp.is_builtin(name) for name in ('sys', '__builtin__', 'exceptions', '__main__', 'imp', 'gc',
                                             '_warnings', 'marshal', 'errno', '_sre', 'no_such_module', u'sys')]
frozen = [imp.is_frozen(name) for name in ('__hello__', '__phello__.spam', 'os')]

held = [imp.lock_held()]
imp.acquire_lock()
held = held + [imp.lock_held()]
imp.acquire_lock()
imp.release_lock()
held = held + [imp.lock_held()]
imp.release_lock()
held = held + [imp.lock_held()]
unlocked = attempt(imp.release_lock)

module = imp.new_module('fresh')
module.value = 5

errors = [
    attempt(imp.new_module, 1),
    attempt(imp.new_module, 'a\0b'),
    attempt(imp.new_module),
    attempt(imp.is_builtin, None),
    attempt(imp.lock_held, 1),
    attempt(imp.get_magic, 1),
    attempt(imp.NullImporter, ''),
    attempt(imp.NullImporter),
]
constants = (imp.SEARCH_ERROR, imp.PY_SOURCE, imp.PY_COMPILED, imp.C_EXTENSION, imp.PY_RESOURCE,
             imp.PKG_DIRECTORY, imp.C_BUILTIN, imp.PY_FROZEN, imp.PY_CODERESOURCE, imp.IMP_HOOK)
RESULT = (imp.get_magic(), suffixes, builtin, frozen, held, unlocked, module.__name__, module.__doc__,
          module.__package__, sorted(module.__dict__), module.value, errors, constants, repr(imp.NullImporter),
          imp.NullImporter.__module__)
