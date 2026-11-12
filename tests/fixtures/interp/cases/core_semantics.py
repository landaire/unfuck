class Quiet(Exception):
    def __init__(self, value):
        self.value = value


class Recoded(Exception):
    def __init__(self, value):
        Exception.__init__(self, 'x', 'y')


def kwargs(**options):
    return list(options)


class Keywords(object):
    def __init__(self, **options):
        self.order = list(options)


class Base(object):
    @classmethod
    def build(cls):
        return cls.__name__

    def method(self):
        return 'base'


class Derived(Base):
    @classmethod
    def build(cls):
        return 'derived ' + super(Derived, cls).build()


def raise_tuple():
    try:
        raise (KeyError, ValueError), 'boom'
    except KeyError as error:
        return error.args


def bad_traceback():
    try:
        raise ValueError, 'x', 5
    except TypeError as error:
        return str(error)


def object_args():
    try:
        object(1)
    except TypeError as error:
        return str(error)


def unbound_super():
    try:
        super(Derived, Derived).method()
    except TypeError as error:
        return 'unbound'


def generator_map():
    seen = []

    def numbers():
        for value in (1, 2, 3):
            seen.append(value)
            yield value
    pairs = map(None, numbers(), 'ab')
    return pairs, seen


cycle = []
cycle.append(cycle)
mapping = {}
mapping['self'] = mapping

RESULT = (
    Quiet(5).args,
    Recoded(1).args,
    str(KeyError('k')),
    kwargs(zeta=1, alpha=2, mu=3, beta=4, omega=5, gamma=6, k=7, kk=8, kkk=9),
    Keywords(zeta=1, alpha=2, mu=3, beta=4, omega=5, gamma=6, k=7, kk=8, kkk=9).order,
    Derived.build(),
    raise_tuple(),
    bad_traceback(),
    object_args(),
    unbound_super(),
    generator_map(),
    repr(cycle),
    repr(mapping),
    cmp({1: 2}, {1: 3}),
    {1: 2, 3: 4} < {1: 2, 3: 5},
    pow(3, 200, 7),
    pow(-3, 3, -7),
    (10L ** 400) / (10L ** 399) if False else None,
    1 is 1,
    () is (),
)
