# object.__new__ refuses classes with Py_TPFLAGS_IS_ABSTRACT, which
# assigning a true __abstractmethods__ sets; type.__abstractmethods__ reads
# only the class's own dict.
import abc


IS_ABSTRACT = 1 << 20


def attempt(function):
    try:
        return ('ok', function())
    except Exception as error:
        return (type(error).__name__, str(error))


def create(cls, *args):
    return attempt(lambda: type(cls(*args)).__name__)


class Base(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def b(self):
        pass

    @abc.abstractmethod
    def a(self):
        pass

    @abc.abstractproperty
    def c(self):
        pass


class Partial(Base):
    def a(self):
        return 1


class Full(Partial):
    c = 3

    def b(self):
        return 2


class Concrete(Base):
    a = b = c = None


class Registered(object):
    pass


Base.register(Registered)


class Meta(abc.ABCMeta):
    pass


class WithMeta(object):
    __metaclass__ = Meta

    @abc.abstractmethod
    def m(self):
        pass


abcs = [
    create(Base),
    create(Partial),
    create(Full),
    Full().a(),
    sorted(Base.__abstractmethods__),
    sorted(Partial.__abstractmethods__),
    Full.__abstractmethods__,
    bool(Base.__flags__ & IS_ABSTRACT),
    bool(Full.__flags__ & IS_ABSTRACT),
    create(Concrete),
    issubclass(Registered, Base),
    create(Registered),
    create(WithMeta),
    type(WithMeta.__abstractmethods__).__name__,
    attempt(lambda: object.__new__(Base)),
]
Concrete.a = abc.abstractmethod(lambda self: None)
abcs.append(create(Concrete))


class Plain(object):
    pass


class Child(Plain):
    pass


class WithInit(object):
    def __init__(self, x):
        pass


class IntSub(int):
    pass


class ListSub(list):
    pass


manual = [
    attempt(lambda: type.__abstractmethods__),
    attempt(lambda: object.__abstractmethods__),
    attempt(lambda: int.__abstractmethods__),
    attempt(lambda: Plain.__abstractmethods__),
    hasattr(Plain, '__abstractmethods__'),
]
Plain.__abstractmethods__ = frozenset(['z', 'y'])
manual += [
    create(Plain),
    attempt(lambda: Plain.__abstractmethods__),
    bool(Plain.__flags__ & IS_ABSTRACT),
    attempt(lambda: Child.__abstractmethods__),
    create(Child),
    attempt(lambda: object.__new__(Plain)),
    attempt(lambda: Plain(1)),
]
Plain.__abstractmethods__ = 1
manual.append(create(Plain))
Plain.__abstractmethods__ = [1, 2]
manual.append(create(Plain))
Plain.__abstractmethods__ = [u'q', 'p']
manual.append(create(Plain))
Plain.__abstractmethods__ = ()
manual.append(create(Plain))
manual.append(bool(Plain.__flags__ & IS_ABSTRACT))
Plain.__abstractmethods__ = ['x']
del Plain.__abstractmethods__
manual += [
    create(Plain),
    bool(Plain.__flags__ & IS_ABSTRACT),
    attempt(lambda: delattr(Plain, '__abstractmethods__')),
]
WithInit.__abstractmethods__ = ('k',)
IntSub.__abstractmethods__ = ('k',)
ListSub.__abstractmethods__ = ('k',)
manual += [
    create(WithInit, 1),
    create(IntSub, 1),
    create(ListSub),
]

RESULT = (abcs, manual)
