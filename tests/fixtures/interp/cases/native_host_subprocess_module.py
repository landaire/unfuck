import subprocess

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except BaseException as e:
        return (type(e).__name__, e.args)

error = subprocess.CalledProcessError(K(3), K('cmd'), K('out'))
common = [
    subprocess.PIPE, subprocess.STDOUT,
    subprocess.list2cmdline([K('a b'), K('c"d'), K('e\\'), K(''), K('f\\\\"g')]),
    str(error), error.returncode, error.cmd, error.output,
    issubclass(subprocess.CalledProcessError, Exception),
    [name for name in ['Popen', 'call', 'check_call', 'check_output', 'list2cmdline'] if hasattr(subprocess, name)],
]

class Info(object):
    dwFlags = K('x')
    wShowWindow = K(0)
    hStdInput = K(0)
    hStdOutput = K(0)
    hStdError = K(0)

class Large(Info):
    dwFlags = K(2 ** 64)

class NotANumberFlags(Info):
    dwFlags = K(float('nan'))

class InfiniteShow(Info):
    dwFlags = K(0)
    wShowWindow = K(float('-inf'))

class HugeFlags(Info):
    dwFlags = K(1e20)

class FractionFlags(Info):
    dwFlags = K(2.5)
    wShowWindow = K('x')

class Hidden(Info):
    hStdError = property(lambda self: 1 / 0)

class Missing(object):
    dwFlags = K('x')

class Classic:
    pass

class ClassicText:
    def __int__(self):
        return 'x'

class Text(object):
    def __int__(self):
        return 'x'

class Huge(object):
    def __int__(self):
        return 2 ** 64

class Fraction(object):
    def __int__(self):
        return 1.5

class Failing(object):
    def __int__(self):
        raise ValueError('boom')

class Plain(object):
    pass

def windows():
    import _subprocess as s
    process = s.GetCurrentProcess()
    handle = [
        type(process).__name__, int(process), process.Detach(), int(process), process.Close(), int(process),
        attempt(process.Close, K(1)), attempt(process.Detach, K(1)), attempt(process.Close, a=K(1)),
        attempt(type(process)), attempt(setattr, process, 'x', K(1)),
        attempt(type, 'Sub', (type(process),), {}),
    ]
    names = sorted(name for name in dir(s) if not name.startswith('__'))
    constants = [(name, getattr(s, name)) for name in names if name.isupper()]
    none = None
    arguments = [
        attempt(s.GetStdHandle), attempt(s.GetStdHandle, K('x')), attempt(s.GetStdHandle, K(1.0)), attempt(s.GetStdHandle, K(2 ** 64)),
        attempt(s.GetCurrentProcess, K(1)), attempt(s.GetVersion, K(1)), attempt(s.GetModuleFileName),
        attempt(s.GetModuleFileName, K('x')), attempt(s.GetModuleFileName, K(2 ** 64)), attempt(s.GetModuleFileName, K(-2 ** 63 - 1)),
        attempt(s.WaitForSingleObject, process), attempt(s.WaitForSingleObject, K(0), K('x')),
        attempt(s.WaitForSingleObject, none, K(0)), attempt(s.WaitForSingleObject, K(0), K(2 ** 64)),
        attempt(s.TerminateProcess, K('a'), K(0)), attempt(s.TerminateProcess, process), attempt(s.TerminateProcess, process, K('x')),
        attempt(s.GetExitCodeProcess, K('a')), attempt(s.GetExitCodeProcess), attempt(s.GetExitCodeProcess, K(1), K(2)),
        attempt(s.DuplicateHandle, K(1), K(2), K(3), K(4)), attempt(s.DuplicateHandle, K(1), K(2), K(3), K('a'), K(5)),
        attempt(s.DuplicateHandle, K(1), K(2), K(3), K(4), K(5), K(6), K(7)), attempt(s.DuplicateHandle, K(1), K(2), K('x'), K(4), K(5)),
        attempt(s.CreatePipe, none), attempt(s.CreatePipe, none, K('x')), attempt(s.CreatePipe, none, K(1.0)),
        attempt(s.CreateProcess, K(1), none, none, none, K(0), K(0), none, none, none),
        attempt(s.CreateProcess, none, K('x'), none, none, K('a'), K(0), none, none, none),
        attempt(s.CreateProcess, none, K('x\0'), none, none, K(0), K(0), none, none, none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), K(5), none, none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), [], none, none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), {K(1): K(2)}, none, none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), {K('a'): K(1)}, none, none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), {K('a'): K('b')}, K(5), none),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, Info()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, Large()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, NotANumberFlags()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, InfiniteShow()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, HugeFlags()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), none, none, FractionFlags()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), {K('a'): K(1)}, none, Hidden()),
        attempt(s.CreateProcess, none, none, none, none, K(0), K(0), {K('a'): K(1)}, none, Missing()),
        attempt(s.GetExitCodeProcess, Classic()), attempt(s.GetExitCodeProcess, ClassicText()),
        attempt(s.GetExitCodeProcess, Text()), attempt(s.GetExitCodeProcess, Huge()),
        attempt(s.GetExitCodeProcess, Fraction()), attempt(s.GetExitCodeProcess, Failing()),
        attempt(s.GetExitCodeProcess, Plain()), attempt(s.GetExitCodeProcess, K(1e300)),
        attempt(s.GetExitCodeProcess, K(float('nan'))), attempt(s.GetExitCodeProcess, K(float('inf'))),
        attempt(s.GetExitCodeProcess, process), attempt(s.WaitForSingleObject, process, K(0)),
        attempt(s.DuplicateHandle, process, process, process, K(0), K(0), K(2)),
        attempt(s.CreateProcess, K('a'), K('b'), none, none, K(0), K(0), none, none),
        attempt(s.CreateProcess, K('a'), K('b'), none, none, K(0), K(0), none, none, none, a=K(1)),
    ]
    info = subprocess.STARTUPINFO()
    module = [
        subprocess.mswindows, sorted(subprocess.__all__),
        [info.dwFlags, info.hStdInput, info.hStdOutput, info.hStdError, info.wShowWindow],
        subprocess.CREATE_NEW_CONSOLE, subprocess.STD_INPUT_HANDLE, subprocess.SW_HIDE,
    ]
    return [handle, names, constants, arguments, module]

RESULT = [common, windows()]
