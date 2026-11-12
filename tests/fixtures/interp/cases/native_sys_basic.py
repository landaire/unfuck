import sys
import exceptions


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


def handled():
    try:
        raise KeyError('inner')
    except KeyError:
        return sys.exc_info()[:2]


try:
    raise ValueError('outer')
except ValueError:
    info = sys.exc_info()
    nested = handled()
    after_nested = sys.exc_info()[1]

limit = sys.getrecursionlimit()
sys.setrecursionlimit(500)
changed = sys.getrecursionlimit()
sys.setrecursionlimit(limit)


def recurse(n):
    return recurse(n + 1)


sys.setrecursionlimit(25)
overflow = error(lambda: recurse(0))
sys.setrecursionlimit(limit)

errors = [error(action) for action in (
    lambda: sys.setrecursionlimit(0),
    lambda: sys.setrecursionlimit(1.5),
    lambda: sys.exc_info(1),
)]

exit_code = None
try:
    sys.exit('bye')
except SystemExit as e:
    exit_code = e.args

flags = sys.flags
RESULT = (info[0] is ValueError, info[1].args, nested[0] is KeyError, after_nested.args, changed, limit, overflow, errors,
          exit_code, sys.maxint, sys.maxsize, sys.byteorder, sys.getdefaultencoding(), sys.version_info,
          sys.version_info.major, sys.version_info.micro, sys.version_info >= (2, 7), sys.hexversion, sys.api_version,
          flags.debug, flags.optimize, flags[0], sys.float_info.max, sys.float_info.epsilon, sys.float_info.dig,
          sys.float_info.mant_dig, sys.float_info[9], sys.modules['sys'] is sys, sys.stdout.write(''),
          sys.stderr.flush(), sys.displayhook(None), sys.getcheckinterval(), sys.py3kwarning,
          exceptions.ValueError is ValueError, exceptions.BytesWarning is BytesWarning, exceptions.BaseException is BaseException,
          isinstance(sys.path, list), sys.subversion, sys.dont_write_bytecode, isinstance(sys.version_info, tuple),
          repr(sys.version_info), error(lambda: type(sys.flags)()), error(lambda: type(sys.version_info)()),
          type(sys.float_info).__name__, len(sys.version_info), [x for x in sys.version_info][3:],
          sys.version_info == tuple(sys.version_info), hash(sys.version_info) == hash(tuple(sys.version_info)),
          error(lambda: setattr(sys.flags, 'debug', 1)), sys.exc_clear(), sys.exc_info())
