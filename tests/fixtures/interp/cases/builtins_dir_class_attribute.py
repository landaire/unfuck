# dir() merges the dict and bases of whatever __class__ returns, and the
# __members__ and __methods__ lists of the object.


def K(value):
    return value


class Base(object):
    z = 1


class FakeClass(object):
    def __init__(self):
        self.__bases__ = [Base]
        self.own = 2


class Disguised(object):
    plain = 3

    @property
    def __class__(self):
        return FakeClass()


class NoBases(object):
    @property
    def __class__(self):
        return K(5)


class Members(object):
    __members__ = [K('m1'), K(7), K('m2')]
    __methods__ = (K('ignored'),)


disguised = dir(Disguised())
RESULT = (
    'z' in disguised,
    '__bases__' in disguised,
    'own' in disguised,
    'plain' in disguised,
    '__init__' in disguised,
    [name for name in dir(NoBases()) if not name.startswith('__')],
    [name for name in dir(Members()) if not name.startswith('__')],
    'z' in dir(Base),
)
