import sys


def inner():
    return sys._getframe()


def outer():
    return inner()


frame = outer()
frames = (type(frame).__name__, frame.f_code.co_name, frame.f_back.f_code.co_name, frame.f_back.f_back.f_code.co_name, frame.f_globals is globals(), frame.f_back.f_back.f_locals is globals())
code_identity = inner.func_code is inner.__code__


class Meta(type):
    def __init__(cls, name, bases, namespace):
        super(Meta, cls).__init__(name, bases, namespace)
        cls.tag = name.lower()


class Tagged(object):
    __metaclass__ = Meta


try:
    type.__init__(Tagged, 1, 2)
    init_arity = 'accepted'
except TypeError as error:
    init_arity = str(error)


class Base(object):
    pass


class Left(Base):
    pass


class Right(Base):
    pass


class Slotted(object):
    __slots__ = ('kind', 'value')
    kind = 'class variable'


def keywords(**kwargs):
    return sorted(kwargs.items())


FunctionType = type(outer)
descriptors = (
    type(FunctionType.func_code).__name__,
    type(FunctionType.func_globals).__name__,
    repr(FunctionType.func_code),
    repr(FunctionType.func_globals),
    FunctionType.func_name.__get__(outer, FunctionType),
    type(Slotted.value).__name__,
    repr(Slotted.value),
    Slotted.kind,
)

RESULT = (
    frames,
    code_identity,
    Tagged.tag,
    init_arity,
    [cls.__name__ for cls in Base.__subclasses__()],
    descriptors,
    keywords(**{u'name': 1}) == [('name', 1)],
    dict(**{u'key': 2}) == {'key': 2},
)
