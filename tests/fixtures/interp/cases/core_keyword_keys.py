def K(value):
    return value


def collect(**kwargs):
    return sorted(kwargs.items())


def named(alpha, beta=2):
    return (alpha, beta)


def attempt(function):
    try:
        return function()
    except TypeError as error:
        return 'TypeError: %s' % error


import _functools as functools

integer_keys = {K(1): 'one', K(2): 'two'}
mixed = {K('a'): 1, K(3): 'three', K(u'b'): 2}

RESULT = (
    dict(**integer_keys),
    dict({K(0): 'zero'}, **integer_keys),
    dict(**mixed),
    attempt(lambda: collect(**integer_keys)),
    collect(**{K(u'name'): 1}),
    repr(collect(**{K(u'name'): 1})[0][0]),
    named(**{K(u'alpha'): 1}),
    attempt(lambda: named(**{K(u'gamma'): 1})),
    attempt(lambda: named(1, **{K(u'alpha'): 1})),
    functools.partial(dict, **integer_keys)(),
    functools.partial(dict, a=1)(**{K(5): 'five'}),
    attempt(lambda: int('5', **integer_keys)),
)
