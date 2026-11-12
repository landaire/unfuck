import sys
import _lsprof

def K(x):
    return x

def attempt(function, *args, **keywords):
    try:
        function(*args, **keywords)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

P = _lsprof.Profiler

class Sub(P):
    pass

def profile_hook_states():
    p = P()
    before = sys.getprofile()
    p.enable()
    during = sys.getprofile() is p
    p.disable()
    after = sys.getprofile()
    p.clear()
    q = P(subcalls=K(0), builtins=K(0))
    q.enable(K(1), K(0))
    replaced = sys.getprofile() is q
    sys.setprofile(None)
    cleared = sys.getprofile()
    q.clear()
    states = [before, during, after, p.getstats(), replaced, cleared, q.getstats()]

    # A profiler still enabled when collected removes whatever hook is
    # installed, even one that displaced it.
    r = P()
    t = P()
    r.enable()
    sys.setprofile(None)
    t.enable()
    del r
    states.append(sys.getprofile())
    u = P()
    u.enable()
    u.disable()
    t.enable()
    del u
    states.append(sys.getprofile() is t)
    t.disable()
    return states

def structure():
    names = [name for name in dir(P) if not name.startswith('__')]
    module_names = sorted(name for name in dir(_lsprof) if not name.startswith('__'))
    return [names, module_names, P.__module__, P.__name__, repr(P), P.__doc__,
            isinstance(Sub(), P), Sub().getstats(),
            hasattr(P(), '__dict__'), attempt(setattr, P(), 'x', 1)]

def entries():
    e = _lsprof.profiler_entry((K(1), 2, 3, 4.5, 5.5, None))
    s = _lsprof.profiler_subentry((K('f'), 1, 0, 0.25, 0.125))
    return [repr(e), e.code, e.callcount, e.reccallcount, e.totaltime, e.inlinetime, e.calls,
            repr(s), s.code, s.inlinetime, len(e), len(s), tuple(e), e[1:3],
            _lsprof.profiler_entry.n_fields, _lsprof.profiler_subentry.n_sequence_fields,
            type(_lsprof.profiler_entry.code).__name__,
            attempt(_lsprof.profiler_entry, (1,)), attempt(_lsprof.profiler_subentry, (1, 2)),
            repr(_lsprof.profiler_entry), repr(_lsprof.profiler_subentry)]

def errors():
    p = P()
    return [
        attempt(P, 1, 2, 3, 4, 5), attempt(P, None, K('x')), attempt(P, foo=1),
        attempt(P, None, timer=1), attempt(P, None, 1.0, 'a'), attempt(P, None, 1.0, 1, 2.5),
        attempt(P, None, 1, 1, 1), attempt(P, subcalls=-5), attempt(P, timeunit=[]),
        attempt(p.enable, 1, 2, 3), attempt(p.enable, 'x'), attempt(p.enable, x=1),
        attempt(p.enable, 1.5), attempt(p.enable, subcalls=1, foo=2),
        attempt(p.getstats, 1), attempt(p.clear, 1), attempt(p.disable, 1), attempt(p.getstats, k=1),
        attempt(P.getstats, 1), attempt(P.enable), attempt(P.__init__, 1), attempt(P.clear),
        attempt(sys.getprofile, 1),
        attempt(P, None, 1.0, K(2 ** 31)), attempt(P, None, 1.0, 1, K(-2 ** 31 - 1)),
        attempt(P, subcalls=K(2 ** 31 - 1)), attempt(p.enable, K(2 ** 31)), attempt(p.disable),
        attempt(p.enable, 1, K(2 ** 32)), attempt(p.disable),
    ]

RESULT = [profile_hook_states(), structure(), entries(), errors(), P().getstats()]
