class Registry(type):
    def __new__(mcs, name, bases, namespace):
        mapping = namespace.get('_TO_NAME')
        if mapping:
            namespace['_FROM_NAME'] = dict((value, key) for key, value in mapping.items())
        namespace['_NAMES'] = tuple(namespace.get('_FROM_NAME', ()))
        return super(Registry, mcs).__new__(mcs, name, bases, namespace)


class Constants(object):
    __metaclass__ = Registry
    _TO_NAME = {}


class Colors(Constants):
    RED = 0
    GREEN = 1
    BLUE = 2
    _TO_NAME = {RED: 'red', GREEN: 'green', BLUE: 'blue'}

    @classmethod
    def name(cls, value):
        return cls._TO_NAME[value]

    @staticmethod
    def count():
        return 3


class Temperature(object):
    def __init__(self):
        self._celsius = 0

    @property
    def celsius(self):
        return self._celsius

    @celsius.setter
    def celsius(self, value):
        self._celsius = value * 2


class Lazy(object):
    def __getattr__(self, name):
        return name.upper()


class A(object):
    def who(self):
        return ['A']


class B(A):
    def who(self):
        return ['B'] + super(B, self).who()


class C(A):
    def who(self):
        return ['C'] + super(C, self).who()


class D(B, C):
    def who(self):
        return ['D'] + super(D, self).who()


temperature = Temperature()
temperature.celsius = 21

RESULT = (
    type(Colors).__name__,
    Colors._NAMES,
    Colors.name(Colors.GREEN),
    Colors.count(),
    temperature.celsius,
    Lazy().missing,
    D().who(),
    [cls.__name__ for cls in D.__mro__],
    isinstance(Colors, Registry),
    issubclass(D, A),
)
