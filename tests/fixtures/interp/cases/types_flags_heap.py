import abc

def K(value):
    return value

results = []

def record(label, cls):
    results.append((label, cls.__flags__))

class Classic:
    pass

class Plain(object):
    pass
record(K('plain'), Plain)

class Empty(object):
    __slots__ = ()
record(K('empty slots'), Empty)

class EmptyChild(Empty):
    __slots__ = ()
record(K('empty slots child'), EmptyChild)

class EmptyChildDict(Empty):
    pass
record(K('empty slots child with dict'), EmptyChildDict)

class Member(object):
    __slots__ = ('x',)
record(K('member slot'), Member)

class DictSlot(object):
    __slots__ = ('__dict__',)
record(K('dict slot'), DictSlot)

class WeakSlot(object):
    __slots__ = ('__weakref__',)
record(K('weakref slot'), WeakSlot)

builtin_bases = [
    int, long, float, complex, str, unicode, basestring, tuple, list, dict, set, frozenset, bytearray,
    type, property, staticmethod, classmethod, super, enumerate, reversed, file, Exception, ValueError,
    BaseException, KeyError, UnicodeDecodeError, StopIteration,
]
for base in builtin_bases:
    record(base.__name__, type('Derived', (base,), {}))
    if base not in (long, str, tuple, type, unicode):
        record(base.__name__ + K(' slotted'), type('Derived', (base,), {'__slots__': ()}))

class Meta(type):
    pass
record(K('metaclass'), Meta)

class WithMeta(object):
    __metaclass__ = Meta
record(K('class with metaclass'), WithMeta)

class Mixed(Classic, object):
    pass
record(K('classic and object'), Mixed)

class MixedChild(Mixed):
    pass
record(K('child of classic mix'), MixedChild)

class Hooks(object):
    def __getattr__(self, name):
        return name
    def __del__(self):
        pass
record(K('hooks'), Hooks)

class Multiple(Plain, Exception):
    pass
record(K('multiple'), Multiple)

class Modified(object):
    pass
class ModifiedChild(Modified):
    pass
Modified.x = K(1)
record(K('after setattr'), Modified)
record(K('child after setattr'), ModifiedChild)
Modified()
record(K('after plain call'), Modified)
Modified.x
record(K('after class lookup'), Modified)
record(K('child after base lookup'), ModifiedChild)
ModifiedChild.y = K(2)
ModifiedChild.y
record(K('child relooked'), ModifiedChild)
record(K('base of relooked child'), Modified)
del Modified.x
record(K('after delattr'), Modified)
Modified().z = K(3)
record(K('after instance setattr'), Modified)

class Init(object):
    def __init__(self):
        pass
Init.x = K(1)
Init()
record(K('after call with __init__'), Init)

class Sized(object):
    def __len__(self):
        return 0
Sized.x = K(1)
len(Sized())
record(K('after len with __len__'), Sized)

class SizedList(list):
    pass
SizedList.x = K(1)
len(SizedList())
record(K('after len inherited'), SizedList)

class Hashed(object):
    def __hash__(self):
        return 1
Hashed.x = K(1)
hash(Hashed())
record(K('after hash'), Hashed)

class Renamed(object):
    pass
Renamed.__name__ = K('Other')
record(K('after rename'), Renamed)

# The method cache takes only exact str names of at most 100 bytes.
class Name(str):
    pass
class Lookups(object):
    pass
lookups = Lookups()
Lookups.x = K(1)
getattr(Lookups, Name(K('x')))
record(K('class lookup by str subclass'), Lookups)
getattr(Lookups, K('y') * 101, None)
record(K('class lookup by long name'), Lookups)
getattr(lookups, Name(K('x')))
hasattr(lookups, Name(K('q')))
setattr(lookups, Name(K('z')), K(1))
record(K('instance access by str subclass'), Lookups)
getattr(lookups, K('q') * 101, None)
record(K('instance lookup by long name'), Lookups)
getattr(Lookups, K('y') * 100, None)
record(K('class lookup by 100 byte name'), Lookups)
setattr(Lookups, Name(K('w')), K(1))
record(K('class setattr by str subclass'), Lookups)
getattr(Lookups, K(u'x'))
record(K('class lookup by unicode'), Lookups)

class First(object):
    pass
class Second(object):
    pass
class Rebased(First):
    pass
Rebased.__bases__ = (Second,)
record(K('after rebase'), Rebased)
Rebased.x = K(1)
Rebased.x
record(K('after rebase relook'), Rebased)
First.x = K(1)
record(K('old base modified'), Rebased)

class Abstract(object):
    __metaclass__ = abc.ABCMeta
    @abc.abstractmethod
    def method(self):
        pass
record(K('abstract'), Abstract)

class Concrete(Abstract):
    def method(self):
        pass
record(K('concrete'), Concrete)
Concrete()
record(K('concrete instantiated'), Concrete)

class Manual(object):
    pass
Manual.__abstractmethods__ = frozenset([K('a')])
record(K('manual abstract'), Manual)
Manual.__abstractmethods__ = frozenset()
record(K('manual empty'), Manual)
Manual.__abstractmethods__ = (K('b'),)
del Manual.__abstractmethods__
record(K('manual deleted'), Manual)

class InDict(object):
    __abstractmethods__ = frozenset([K('a')])
record(K('abstract in namespace'), InDict)

record(K('type'), type)
record(K('ABCMeta'), abc.ABCMeta)

RESULT = results
