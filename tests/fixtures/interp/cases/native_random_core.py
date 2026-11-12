# _random.Random directly. Not asserted: the SystemError message (it names
# the build's source path).
import _random


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


def draws(r, n=3):
    return [r.random() for _ in range(n)]


out = []
r = _random.Random(K(42))
out.append(draws(r))
out.append([r.getrandbits(K(n)) for n in (1, 5, 31, 32, 33, 64, 100)])

for seed in (0, 1, -1, 42, -42, 2 ** 32 - 1, 2 ** 32, 2 ** 70 + 5, -(2 ** 70 + 5), 10 ** 40, True, False, 7L, 2.0, -0.0):
    r.seed(K(seed))
    out.append((repr(seed), draws(r, 2)))

for seed in ('abc', u'abc', '', 'a much longer seed string', (1, 2), 3 + 4j, 2.5):
    r.seed(K(seed))
    out.append((repr(seed), draws(r, 2)))

r.seed(K(12345))
state = r.getstate()
out.append((len(state), state[:3], state[-1], type(state[0]).__name__, type(state[-1]).__name__))
first = draws(r, 4)
r.setstate(state)
out.append(first == draws(r, 4))
out.append(r.getstate()[-1])

r.setstate((1,) * 624 + (624,))
out.append(draws(r))
r.setstate((5L,) * 624 + (0,))
out.append(draws(r))
r.setstate(tuple(range(624)) + (3.9,))
out.append((r.getstate()[-1], draws(r)))
out.append(r.setstate((True,) * 624 + (True,)))
out.append(r.getstate()[-1])

r.seed(K(11))
out.append(err(r.setstate, (2 ** 32,) * 624 + (1,)))
out.append(draws(r))
r.setstate((2 ** 32 - 1,) * 624 + (1,))
out.append(draws(r))
out.append(err(r.setstate, (1,) * 624 + (2 ** 32,)))
out.append(draws(r))
out.append(err(r.setstate, (1,) * 624 + (2 ** 31,)))
out.append(err(r.setstate, (1,) * 624 + (2 ** 40 + 1,)))
r.seed(K(5))
out.append(err(r.setstate, (1,) * 623 + ('x', 1))[0])
out.append((r.getstate()[:3], r.getstate()[-1], draws(r)))
out.append(err(r.setstate, (-1,) * 625))
out.append((r.getstate()[-1], draws(r)))


class Absolute(int):
    def __abs__(self):
        return 7


class AbsoluteLong(long):
    def __abs__(self):
        return 7L


r.seed(Absolute(3))
out.append(draws(r))
r.seed(AbsoluteLong(3))
out.append(draws(r))

r.seed(K(7))
r.jumpahead(K(1))
out.append(draws(r))
r.jumpahead(K(2 ** 100 + 3))
out.append(draws(r))
r.jumpahead(K(-5))
out.append(draws(r))
r.jumpahead(K(True))
out.append((draws(r), r.getstate()[-1]))

r.seed(K(99))
before = r.getstate()
r.jumpahead(K(0))
out.append(r.getstate() == before)


class Big(long):
    def __mod__(self, other):
        return 0


r.seed(K(3))
r.jumpahead(Big(17))
out.append(draws(r))

out.append(err(_random.Random, 1, 2))
out.append(err(_random.Random, x=1))
out.append(err(r.seed, 1, 2))
out.append(err(r.seed, a=1))
out.append(err(r.seed, []))
out.append(err(r.setstate, [1] * 625))
out.append(err(r.setstate, (1,) * 624))
out.append(err(r.setstate, (-1,) * 625))
out.append(err(r.setstate, (1,) * 624 + (625,)))
out.append(err(r.setstate, (1,) * 624 + (-1,)))
out.append(err(r.setstate, (1,) * 624 + ('x',)))
out.append(err(r.setstate, (1,) * 624 + (None,))[0])
out.append(err(r.setstate, (1.0,) * 625)[0])
out.append(err(r.setstate))
out.append(err(r.jumpahead, 1.0))
out.append(err(r.jumpahead, '1'))
out.append(err(r.jumpahead))
out.append(err(r.getrandbits, 0))
out.append(err(r.getrandbits, -3))
out.append(err(r.getrandbits, 1.0))
out.append(err(r.getrandbits, 'a'))
out.append(err(r.getrandbits))
out.append(err(r.random, 1))
out.append(err(r.getstate, 1))
out.append(err(_random.Random.random, 1))
out.append(err(_random.Random.seed))


class Sub(_random.Random):
    def __init__(self, seed, tag=None):
        self.tag = tag


s = Sub(5, tag='t')
out.append((s.tag, draws(s, 2), isinstance(s, _random.Random)))
out.append(err(Sub, 1, 2))
out.append(Sub.__mro__)
out.append(_random.Random.__module__)
out.append(sorted(k for k in _random.Random.__dict__ if not k.startswith('__')))

RESULT = out
