# An AttributeError raised by __getattribute__ or __getattr__ belongs to
# that lookup only: a hook that recovers, or a nested lookup inside a hook,
# leaves later lookups with their own errors.


def K(value):
    return value


def err(f, *a):
    try:
        return ('ok', f(*a))
    except Exception as e:
        return (type(e).__name__, e.args)


class Recovering(object):
    def __getattribute__(self, name):
        raise AttributeError(K('from getattribute ') + name)

    def __getattr__(self, name):
        return K('recovered ') + name


class Strict(object):
    def __getattribute__(self, name):
        raise AttributeError(K('strict ') + name)


class Failing(object):
    def __getattr__(self, name):
        raise AttributeError(K('failing ') + name)


class Nested(object):
    def __getattr__(self, name):
        hasattr(Failing(), 'inner')
        if name == 'present':
            return K(1)
        raise AttributeError(K('nested ') + name)


class Probing(object):
    def __getattr__(self, name):
        return hasattr(Strict(), name)


class ClassicNested:
    def __getattr__(self, name):
        getattr(Failing(), 'inner', None)
        raise AttributeError(K('classic ') + name)


class Plain(object):
    pass


RESULT = (
    err(getattr, Recovering(), 'a'), err(getattr, Plain(), 'b'),
    hasattr(Strict(), 'c'), err(getattr, Plain(), 'd'),
    err(getattr, Strict(), 'e'), err(getattr, Failing(), 'f'),
    err(getattr, Nested(), 'present'), err(getattr, Nested(), 'g'),
    err(getattr, Probing(), 'h'), err(getattr, Plain(), 'i'),
    err(getattr, ClassicNested(), 'j'), err(lambda: Plain().k),
    getattr(Failing(), 'l', K(5)), err(lambda: Recovering().m),
)
