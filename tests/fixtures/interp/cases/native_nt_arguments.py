import nt

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

m = nt
RESULT = [
    attempt(m.stat), attempt(m.stat, 1), attempt(m.stat, 'a\0b'), attempt(m.stat, None), attempt(m.stat, 'x', k=1),
    attempt(m.lstat, 1), attempt(m.access, 1, 1), attempt(m.access, 'x'), attempt(m.access, 'x', 'y'),
    attempt(m.chmod, 'x'), attempt(m.mkdir, 1), attempt(m.mkdir, 'x', 'y'), attempt(m.listdir, 1), attempt(m.listdir),
    attempt(m.open, 'x'), attempt(m.open, 1, 0), attempt(m.open, 'x', 'y'), attempt(m.open, 'a', 1, 2, 3),
    attempt(m.read, 1), attempt(m.read, 1, 'x'), attempt(m.read, -1, -1),
    attempt(m.write, 1), attempt(m.write, 1, 2), attempt(m.close, 'x'), attempt(m.close), attempt(m.dup, 1.5),
    attempt(m.dup2, 1), attempt(m.lseek, 1, 'x', 0), attempt(m.lseek, 1, 0),
    attempt(m.fdopen, 'x'), attempt(m.fdopen), attempt(m.fdopen, 0, ''), attempt(m.fdopen, 0, 'q'),
    attempt(m.fdopen, 0, 'wU'), attempt(m.fdopen, 0, 1),
    attempt(m.fstat, 1.5), attempt(m.isatty), attempt(m.getcwd, 1), attempt(m.getcwdu, 1), attempt(m.getcwd, k=1),
    attempt(m.getpid, 1), attempt(m.times, 1), attempt(m.pipe, 1), attempt(m.umask, 'x'),
    attempt(m.urandom, -1), attempt(m.urandom, 'x'), attempt(m.urandom, 1.5),
    # putenv('', 'b') is left out: under Wine the failing _putenv leaves errno
    # as the previous call set it, so the OSError's errno is not the CRT's.
    attempt(m.putenv, 'a'), attempt(m.putenv, 'a=b', 'c'), attempt(m.putenv, 1, 'c'),
    attempt(m.system, 1), attempt(m.popen, 1), attempt(m.popen, 'x', 1), attempt(m.popen, 'x', 'r', 'y'),
    attempt(m.waitpid, 1), attempt(m.waitpid, 1, 'x'), attempt(m.utime, 1), attempt(m.utime, 'x'),
    attempt(m.rename, 'x'), attempt(m._exit, 'x'), attempt(m._exit),
    attempt(m.execv, 1, 2), attempt(m.execv, 'x'), attempt(m.execv, 'x', 5), attempt(m.execv, 'x', []),
    attempt(m.execv, 'x', [1]), attempt(m.execve, 'x', 5, {}), attempt(m.execve, 'x', ['a'], 5),
    attempt(m.fsync, 'x'), attempt(m.fsync, 1.5), attempt(m.fsync, -1), attempt(m.fsync),
    attempt(m.closerange, 1), attempt(m.tempnam, 1), attempt(m.tempnam, None, 2),
    attempt(m.tmpfile, 1), attempt(m.tmpnam, 1), attempt(m.abort, 1), attempt(m.isatty, 'x'),
]
