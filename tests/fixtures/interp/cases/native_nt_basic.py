try:
    import nt as os_module
except ImportError:
    import posix as os_module

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

constants = [getattr(os_module, name) for name in ('F_OK', 'R_OK', 'W_OK', 'X_OK', 'O_RDONLY', 'O_WRONLY', 'O_RDWR')]
messages = [os_module.strerror(code) for code in (1, 2, 3, 9, 10, 13, 17, 19, 20, 21, 22, 23, 24, 28, 30, 31, 32)]
result = os_module.stat_result((1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
stat = (result.st_mode, result.st_ino, result.st_size, result.st_atime, result.st_mtime, result.st_ctime,
        result[7], result[-1], len(result), result == (1, 2, 3, 4, 5, 6, 7, 8, 9, 10), type(result).__name__)

float_times = [os_module.stat_float_times(), os_module.stat_float_times(-1), os_module.stat_float_times(0),
               os_module.stat_float_times(), os_module.stat_float_times(1), os_module.stat_float_times()]

errors = [
    attempt(os_module.strerror, 'x'),
    attempt(os_module.strerror),
    attempt(os_module.stat_float_times, 'x'),
]
present = [hasattr(os_module, name) for name in ('_exit', 'getpid', 'stat', 'listdir', 'urandom', 'open', 'close')]
RESULT = (constants, messages, stat, float_times, errors, present, os_module.error is OSError,
          isinstance(os_module.environ, dict), type(os_module.stat_result).__name__)
