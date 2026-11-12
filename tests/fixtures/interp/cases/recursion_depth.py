# Recursion to sys.getrecursionlimit(): which check fails first, after how
# many levels, and with which message. Each scenario runs with a fixed
# number of levels left, so the results do not depend on the depth at
# which the module body runs. Nested dicts are not passed to repr: dict
# repr has no recursion check, so a deep enough one crashes CPython.
import json
import sys


def K(value):
    return value


def remaining():
    def probe(n):
        try:
            return probe(n + 1)
        except RuntimeError:
            return n

    return probe(0)


HEADROOM = 40


def at_headroom(scenario):
    def descend(n):
        if n == 0:
            return scenario()
        return descend(n - 1)

    return descend(remaining() - HEADROOM)


def describe(outcome):
    count, error = outcome
    return count, type(error).__name__, str(error)


def deepest(build, action):
    # The deepest nesting `action` handles, and the error one level past it.
    levels = 0
    while True:
        value = build(levels + 1)
        try:
            action(value)
        except RuntimeError as error:
            return levels, error
        levels += 1


def nest_list(levels):
    value = []
    for _ in range(levels):
        value = [value]
    return value


def nest_tuple(levels):
    value = ()
    for _ in range(levels):
        value = (value,)
    return value


def nest_dict(levels):
    value = {}
    for _ in range(levels):
        value = {K('a'): value}
    return value


def nest_pair(nest):
    return lambda levels: (nest(levels), nest(levels))


def plain():
    def call(n):
        try:
            return call(n + 1)
        except RuntimeError as error:
            return n, error

    return call(0)


def keyword():
    def call(n):
        try:
            return call(n=n + 1)
        except RuntimeError as error:
            return n, error

    return call(0)


def star():
    def call(n):
        try:
            return call(*(n + 1,))
        except RuntimeError as error:
            return n, error

    return call(0)


def star_keywords():
    def call(n):
        try:
            return call(**{K('n'): n + 1})
        except RuntimeError as error:
            return n, error

    return call(0)


def through_map():
    def call(n):
        try:
            return map(call, [n + 1])[0]
        except RuntimeError as error:
            return n, error

    return call(0)


def through_apply():
    def call(n):
        try:
            return apply(call, (n + 1,))
        except RuntimeError as error:
            return n, error

    return call(0)


class Node(object):
    def method(self, n):
        try:
            return self.method(n + 1)
        except RuntimeError as error:
            return n, error

    def unbound(self, n):
        try:
            return Node.unbound(self, n + 1)
        except RuntimeError as error:
            return n, error

    def __call__(self, n):
        try:
            return self(n + 1)
        except RuntimeError as error:
            return n, error

    def __getattr__(self, name):
        try:
            return getattr(self, name + K('x'))
        except RuntimeError as error:
            return len(name), error


class Classic:
    def __call__(self, n):
        try:
            return self(n + 1)
        except RuntimeError as error:
            return n, error

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        try:
            return getattr(self, name + K('x'))
        except RuntimeError as error:
            return len(name), error


constructed = []


class Construct(object):
    def __init__(self, n):
        try:
            Construct(n + 1)
        except RuntimeError as error:
            constructed.append((n, error))


def construct():
    del constructed[:]
    Construct(0)
    return constructed[0]


class Chain(object):
    def __init__(self, child):
        self.child = child

    def __str__(self):
        return str(self.child)

    def __repr__(self):
        return 'Chain(%r)' % (self.child,)

    def __eq__(self, other):
        return self.child == other.child


def chain(levels):
    value = None
    for _ in range(levels):
        value = Chain(value)
    return value


def generator():
    def produce(n):
        try:
            yield next(produce(n + 1))
        except RuntimeError as error:
            yield n, error

    return next(produce(0))


class Recursive(object):
    def __init__(self):
        self.depth = 0

    def __repr__(self):
        self.depth += 1
        return repr(self)


def recursive_repr():
    target = Recursive()
    try:
        repr(target)
    except RuntimeError as error:
        return target.depth, error


calls = [describe(at_headroom(scenario)) for scenario in (
    plain,
    keyword,
    star,
    star_keywords,
    through_map,
    through_apply,
    lambda: Node().method(0),
    lambda: Node().unbound(0),
    lambda: Node()(0),
    lambda: Node().x,
    lambda: Classic()(0),
    lambda: Classic().x,
    construct,
    generator,
    recursive_repr,
)]

nested = [describe(at_headroom(lambda: deepest(build, action))) for build, action in (
    (chain, str),
    (nest_pair(nest_list), lambda pair: pair[0] == pair[1]),
    (nest_pair(nest_tuple), lambda pair: pair[0] < pair[1]),
    (nest_pair(nest_dict), lambda pair: pair[0] == pair[1]),
    (nest_pair(nest_list), lambda pair: cmp(pair[0], pair[1])),
    (nest_pair(chain), lambda pair: pair[0] == pair[1]),
    (lambda levels: K('[') * levels + K(']') * levels, json.loads),
    (lambda levels: K(u'[') * levels + K(u']') * levels, json.loads),
    (lambda levels: K('{"a":') * levels + K('1') + K('}') * levels, json.loads),
    (lambda levels: K(u'{"a":') * levels + K(u'1') + K(u'}') * levels, json.loads),
    (nest_list, json.dumps),
    (nest_dict, json.dumps),
    (nest_list, lambda value: json.dumps(value, indent=1)),
    (nest_list, repr),
    (nest_tuple, repr),
    (chain, repr),
    (nest_list, str),
    (lambda levels: [nest_tuple(levels)], repr),
)]


def endless():
    return endless()


def from_module(action):
    try:
        action()
    except RuntimeError as error:
        return str(error)


# Recursion from the module body without a fixed headroom.
direct = (
    from_module(lambda: json.loads(K('[') * 100000)),
    from_module(lambda: json.loads(K(u'{"a":') * 100000)),
    from_module(lambda: json.dumps(nest_list(100000))),
    from_module(lambda: nest_list(100000) == nest_list(100000)),
    from_module(lambda: repr(nest_list(100000))),
    from_module(lambda: repr(nest_tuple(100000))),
    from_module(endless),
)

RESULT = (calls, nested, direct)
