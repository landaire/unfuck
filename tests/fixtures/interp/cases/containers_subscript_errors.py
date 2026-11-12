def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, e.args)


class Plain(object):
    pass


class IntSub(int):
    pass


class Old:
    pass


class OldTrunc:
    def __trunc__(self):
        return 4


class OldTruncFloat:
    def __trunc__(self):
        return 5.5


class OldLong:
    def __long__(self):
        return 7L


def item(container, key):
    return container[key]


RESULT = (
    err(item, Plain(), 0), err(item, Plain(), 'a'), err(item, Plain(), True), err(item, IntSub(5), 0),
    err(item, set(), 0), err(item, frozenset(), 0), err(item, {}.viewkeys(), 0), err(item, object(), 0),
    err(item, 5, 0), err(item, None, 0), err(item, Old(), 0),
    err(item, u'abc', 'a'), err(item, u'abc', 1.5), err(item, 'abc', 'a'),
    err(int, Old()), int(OldTrunc()), int(OldTruncFloat()), long(OldTrunc()), err(long, Old()), err(int, OldLong()),
)
