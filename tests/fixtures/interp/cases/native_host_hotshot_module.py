import _hotshot
import hotshot
import cProfile

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

H = _hotshot

def constants():
    return sorted((name, getattr(H, name)) for name in dir(H) if name.startswith('WHAT_'))

def structure():
    names = sorted(name for name in dir(H) if not name.startswith('__'))
    profiler_names = [name for name in dir(H.ProfilerType) if not name.startswith('__')]
    reader_names = [name for name in dir(H.LogReaderType) if not name.startswith('__')]
    return [names, profiler_names, reader_names, H.__version__,
            repr(H.ProfilerType), repr(H.LogReaderType),
            H.ProfilerError.__module__, H.ProfilerError.__name__, [c.__name__ for c in H.ProfilerError.__mro__],
            type(H.ProfilerType.closed).__name__,
            type(H.ProfilerType.lineevents).__name__,
            type(H.LogReaderType.info).__name__,
            hasattr(H.LogReaderType, 'next'), hasattr(H.LogReaderType, '__iter__'),
            hasattr(H.LogReaderType, '__getitem__')]

def errors():
    class Sub(object):
        pass
    return [
        attempt(H.profiler), attempt(H.profiler, K(1)), attempt(H.profiler, 'a', 'x'),
        attempt(H.profiler, 'a', 1, 2, 3), attempt(H.profiler, K('a\0b')), attempt(H.profiler, u'a', 1.5),
        attempt(H.profiler, 'a', kw=1), attempt(H.coverage), attempt(H.coverage, 'a', 1),
        attempt(H.coverage, None), attempt(H.logreader, None), attempt(H.logreader),
        attempt(H.logreader, 'a', 'b'), attempt(H.resolution, 1), attempt(H.resolution, kw=1),
        attempt(H.ProfilerType), attempt(H.LogReaderType),
        attempt(H.ProfilerType.close, 1), attempt(H.ProfilerType.start), attempt(H.LogReaderType.next, 1),
        attempt(H.LogReaderType.fileno, 'x'), attempt(H.ProfilerType.addinfo, None, 'a', 'b'),
        attempt(H.ProfilerType.closed.__get__, 1), attempt(H.LogReaderType.info.__get__, 1),
        attempt(type, 'X', (H.ProfilerType,), {}), attempt(type, 'Y', (H.LogReaderType,), {}),
        attempt(H.ProfilerError, 'm'),
    ]

def wrappers():
    return [hotshot.ProfilerError is H.ProfilerError, hotshot.Profile.__name__,
            cProfile.Profile.__bases__, cProfile.Profile.__module__, cProfile.__all__,
            hasattr(cProfile, 'runctx'), cProfile.label(K('x')), cProfile.Profile().getstats(),
            isinstance(cProfile.Profile(), __import__('_lsprof').Profiler)]

RESULT = [constants(), structure(), errors(), wrappers(), type(H.resolution()).__name__, len(H.resolution())]
