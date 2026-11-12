def counter(limit):
    received = []
    index = 0
    while index < limit:
        value = yield index
        received.append(value)
        index += 1
    yield received


def guarded():
    try:
        yield 1
        yield 2
    except KeyError as error:
        yield 'caught %s' % error.args[0]
    finally:
        cleanup.append('done')


def make_adders():
    adders = []
    for step in (1, 2, 3):
        def add(value, step=step):
            return value + step
        adders.append(add)
    return adders


def outer():
    count = [0]

    def inner():
        count[0] += 1
        return count[0]
    inner()
    inner()
    return inner()


def keywords(*args, **kwargs):
    return args, list(kwargs)


cleanup = []
generator = counter(3)
first = generator.next()
second = generator.send('a')
third = generator.send('b')
last = generator.send('c')

protected = guarded()
started = protected.next()
caught = protected.throw(KeyError('k'))
protected.close()

squares = list(x * x for x in range(5) if x % 2 == 0)
nested = [(a, b) for a in range(3) for b in range(a)]

RESULT = (first, second, third, last, started, caught, cleanup, squares, nested, [add(10) for add in make_adders()], outer(), keywords(1, 2, zeta=1, alpha=2, mu=3, beta=4, omega=5, gamma=6))
