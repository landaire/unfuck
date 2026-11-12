# Values of __slots__ members live outside the instance dict; a class whose
# __slots__ leave out __dict__ has no instance dict at all.
import weakref


def attempt(function):
    try:
        return ('ok', function())
    except Exception as error:
        return (type(error).__name__, str(error))


class Pair(object):
    __slots__ = ('a', 'b', '__hidden')

    def store(self):
        self.__hidden = 'h'


pair = Pair()
storage = [
    attempt(lambda: pair.a),
    attempt(lambda: pair.__dict__),
    attempt(lambda: vars(pair)),
]
pair.a = 1
pair.store()
storage += [
    attempt(lambda: pair.a),
    attempt(lambda: pair._Pair__hidden),
    attempt(lambda: setattr(pair, 'c', 1)),
    attempt(lambda: setattr(pair, '__dict__', {})),
    attempt(lambda: delattr(pair, 'b')),
    attempt(lambda: delattr(pair, 'a')),
    attempt(lambda: pair.a),
    attempt(lambda: delattr(pair, 'c')),
    sorted(Pair.__dict__),
]

descriptor = Pair.__dict__['a']
descriptors = [
    type(descriptor).__name__,
    repr(descriptor).split(' at ')[0],
    repr(Pair.__dict__['_Pair__hidden']).split(' at ')[0],
    descriptor.__name__,
    descriptor.__objclass__ is Pair,
    descriptor.__doc__,
    Pair.a is descriptor,
    descriptor.__get__(None, Pair) is descriptor,
    attempt(lambda: descriptor.__get__(1)),
    attempt(lambda: descriptor.__set__(1, 2)),
    attempt(lambda: descriptor.__delete__(1)),
    attempt(lambda: descriptor.__get__(pair, Pair)),
]
descriptor.__set__(pair, 5)
descriptors.append(pair.a)
descriptor.__delete__(pair)
descriptors.append(attempt(lambda: pair.a))


class Base(object):
    __slots__ = ('a',)


class Derived(Base):
    __slots__ = ('b', 'a')


derived = Derived()
derived.a = 1
Base.a.__set__(derived, 7)
inherited = [
    (derived.a, Base.a.__get__(derived)),
    Derived.a is Base.a,
    attempt(lambda: derived.__dict__),
    sorted(name for name in dir(derived) if not name.startswith('__')),
]


class Open(Base):
    pass


opened = Open()
opened.a = 3
opened.q = 4
inherited += [
    opened.__dict__,
    vars(opened),
    type(Open.__dict__['__dict__']).__name__,
    type(Open.__dict__['__weakref__']).__name__,
]


class WithDict(object):
    __slots__ = ('__dict__', 'h')


with_dict = WithDict()
with_dict.h = 1
with_dict.k = 2
dicts = [
    with_dict.__dict__,
    attempt(lambda: with_dict.__weakref__),
    attempt(lambda: setattr(with_dict, '__dict__', 5)),
]
with_dict.__dict__ = {'n': 1}
dicts.append((with_dict.n, with_dict.h))
del with_dict.__dict__
dicts.append(with_dict.__dict__)


class ClassVariable(object):
    __slots__ = ('a',)
    a = 5


class Duplicate(object):
    __slots__ = ('a', 'a')


class FromString(object):
    __slots__ = 'one'


class FromList(object):
    __slots__ = ['p', 'q']


class FromIterator(object):
    __slots__ = iter(['m', 'n'])


class Empty(object):
    __slots__ = ()


duplicate = Duplicate()
duplicate.a = 1
shapes = [
    ClassVariable().a,
    attempt(lambda: setattr(ClassVariable(), 'a', 1)),
    duplicate.a,
    sorted(name for name in FromString.__dict__ if not name.startswith('__')),
    FromList.__slots__,
    sorted(name for name in FromIterator.__dict__ if len(name) == 1),
    type(FromIterator.__slots__).__name__,
    attempt(lambda: Empty().__dict__),
    attempt(lambda: setattr(Empty(), 'x', 1)),
]


class Weak(object):
    __slots__ = ('__weakref__',)


weak = Weak()
first = weakref.ref(weak)
weakrefs = [
    weak.__weakref__ is first,
    attempt(lambda: weakref.ref(pair)),
    attempt(lambda: weakref.ref(with_dict)),
    attempt(lambda: pair.__weakref__),
    weakref.ref(opened)() is opened,
    attempt(lambda: setattr(weak, '__weakref__', None)),
]
del first
weakrefs.append(weak.__weakref__)

RESULT = (storage, descriptors, inherited, dicts, shapes, weakrefs)
