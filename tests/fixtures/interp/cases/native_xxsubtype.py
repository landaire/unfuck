# xxsubtype. Not asserted: bench timings (host clock).
import xxsubtype as x


def err(fn, *a, **k):
    try:
        return ('ok', fn(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


out = []
L = x.spamlist([1, 2])
out.append((L, repr(L), L.state, L.getstate(), L.setstate(5), L.state, L.getstate()))
out.append(err(L.setstate))
out.append(err(L.setstate, 1.0))
out.append(err(L.setstate, 'a'))
out.append(err(L.setstate, 2 ** 31))
out.append(err(L.setstate, -2 ** 31 - 1))
out.append(err(L.setstate, 2 ** 31 - 1))
out.append(err(L.setstate, 2 ** 64))
out.append(err(L.getstate, 1))
out.append(err(L.setstate, 1, k=2))
out.append(err(setattr, L, 'state', 3))
out.append(err(setattr, L, 'foo', 3))
out.append(err(delattr, L, 'state'))
out.append(x.spamlist.__mro__)
out.append((x.spamlist.__module__, x.spamlist.__name__))
out.append(x.spamlist.classmeth(1, a=2))
out.append(L.classmeth())
out.append(x.spamlist.staticmeth(1, k=2))
out.append(L.staticmeth())
out.append((type(x.spamlist.__dict__['state']).__name__, type(x.spamdict.__dict__['state']).__name__))
out.append((repr(x.spamlist.__dict__['state']), repr(x.spamdict.__dict__['state'])))
list_state = x.spamlist.__dict__['state']
dict_state = x.spamdict.__dict__['state']
out.append(err(list_state.__get__, {}))
out.append(err(list_state.__get__, x.spamdict()))
out.append(err(dict_state.__get__, []))
out.append(err(dict_state.__get__, x.spamlist()))
out.append(err(dict_state.__get__, 3))
out.append((list_state.__get__(None, x.spamlist) is list_state, list_state.__get__(x.spamlist([1]))))

D = x.spamdict(a=1)
out.append((D, D.state, D.setstate(-4), D.state, D.getstate()))
out.append(err(setattr, D, 'state', 3))
out.append(err(x.spamdict.getstate, {}))
out.append(err(x.spamlist.setstate, [], 1))
out.append(err(x.spamlist.getstate))
D.__init__(b=2)
out.append((sorted(D.items()), D.state))


class S(x.spamlist):
    pass


s = S([3])
s.setstate(9)
out.append((s, s.state, S.classmeth(), s.__dict__, type(s).__name__))
L.__init__([7])
out.append((L, L.state))
out.append(err(x.spamlist, 1))
out.append((L == [7], L + [1], type(L + [1]).__name__, type(L[:]).__name__, len(L)))


class Probe(object):
    count = 0

    @property
    def value(self):
        Probe.count += 1
        return 1


p = Probe()
x.bench(p, 'value')
x.bench(p, 'value', 5)
x.bench(p, 'value', -2)
out.append(Probe.count)
out.append(err(x.bench))
out.append(err(x.bench, 1, 2))
out.append(err(x.bench, 1, 'real', 1.5))
out.append(err(x.bench, 1, 'nope', 2))
out.append(err(x.bench, 1, u'real'))
out.append(err(x.bench, 1, 'real', 1, 2))
out.append(err(x.bench, 1, 'real', n=1))
out.append(sorted(k for k in dir(x) if not k.startswith('__')))

RESULT = out
