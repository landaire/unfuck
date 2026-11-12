from _functools import partial, reduce


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


def collect(*args, **kwargs):
    return args, sorted([(k, kwargs[k]) for k in kwargs])


base = partial(collect, 1, 2, a=1)
nested = partial(partial(max, 1), 5)
plain = partial(collect)
plain.label = 'tagged'


class Tagged(partial):
    pass


tagged = Tagged(collect, 'x')

errors = [error(action) for action in (
    lambda: partial(),
    lambda: partial(1),
    lambda: setattr(base, 'func', None),
    lambda: delattr(base, 'args'),
    lambda: setattr(plain, '__dict__', 1),
    lambda: partial(error)(1, 2),
    lambda: partial(error, 1)(action=2),
)]

RESULT = (base(3, b=2), base(a=9), nested(3), plain(), plain.keywords, base.keywords, base.args, base.func is collect,
          plain.label, plain.__dict__, tagged(1), type(tagged).__name__, tagged.args, errors,
          partial.__module__, base.__reduce__()[1][0] is collect, base.__reduce__()[2][1:3], reduce(lambda x, y: x * y, [1, 2, 3, 4]),
          reduce(lambda x, y: x + y, [], 10), isinstance(tagged, partial), repr(type(base)))
