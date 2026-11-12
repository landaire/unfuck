# random.py over _random. Module-level and unseeded generators draw from
# os.urandom, so only seeded results are asserted.
import copy
import random


def K(value):
    return value


# Variates computed with CRT transcendental functions compare to 12
# significant digits: Wine's CRT rounds those differently from msvcr90 in
# the last ulp.
def libm(value):
    return '%.12g' % value


out = []
random.seed(K(42))
out.append(random.random())
items = list(range(10))
random.shuffle(items)
out.append(items)
out.append([random.choice('abcdefg') for _ in range(5)])
out.append([random.randint(1, 6) for _ in range(8)])
out.append(random.sample(range(100), 5))
out.append(random.sample('hello', 3))
out.append([libm(random.gauss(0, 1)) for _ in range(3)])
out.append([random.uniform(-2, 5) for _ in range(3)])
out.append([random.randrange(0, 100, 7) for _ in range(4)])
out.append(random.randrange(10 ** 30))
out.append(random.getrandbits(70))
out.append(random.triangular(0, 10, 3))
out.append(libm(random.expovariate(1.5)))
out.append(libm(random.normalvariate(10, 2)))
out.append(libm(random.lognormvariate(0, 1)))
out.append(libm(random.vonmisesvariate(1, 2)))
out.append(libm(random.gammavariate(2, 3)))
out.append(libm(random.betavariate(2, 5)))
out.append(libm(random.paretovariate(3)))
out.append(libm(random.weibullvariate(1, 2)))

g = random.Random(K(2024))
state = g.getstate()
out.append((state[0], len(state[1]), state[2]))
a = [g.random() for _ in range(3)]
g.setstate(state)
out.append(a == [g.random() for _ in range(3)])

g.jumpahead(K(10))
out.append(g.random())

g.seed(K('not asserted'))
g.seed(K(77))
c = copy.copy(g)
d = copy.deepcopy(g)
out.append((type(c) is random.Random, c.random() == g.random(), d.random() == c.random()))
out.append(g.__reduce__()[0] is random.Random)

h = random.Random()
h.seed(K(5))
out.append(h.random())
unseeded = random.Random()
unseeded.random()

w = random.WichmannHill(K(3))
out.append([w.random() for _ in range(2)])
w.jumpahead(K(4))
out.append(w.random())

try:
    g.setstate((9, (), None))
except ValueError as e:
    out.append(str(e))

RESULT = out
