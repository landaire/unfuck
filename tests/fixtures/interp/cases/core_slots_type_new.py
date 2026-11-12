# type_new's __slots__ checks, name mangling, and the solid base that
# decides instance lay-out conflicts.


def make(name, bases, namespace):
    try:
        cls = type(name, bases, namespace)
    except Exception as error:
        return (type(error).__name__, str(error))
    return sorted(key for key in cls.__dict__ if key not in ('__module__', '__doc__', '__slots__'))


class Slotted(object):
    __slots__ = ('x',)


class Other(object):
    __slots__ = ('y',)


class Nothing(object):
    __slots__ = ()


class Plain(object):
    pass


class Classic:
    pass


class WeakOnly(object):
    __slots__ = ('__weakref__',)


class DictOnly(object):
    __slots__ = ('__dict__',)


class Tuple1(tuple):
    pass


class Tuple2(tuple):
    pass


class EmptyTuple(tuple):
    __slots__ = ()


errors = [
    make('B', (object,), {'__slots__': ('__dict__', '__dict__')}),
    make('B', (object,), {'__slots__': ('__weakref__', '__weakref__')}),
    make('B', (WeakOnly,), {'__slots__': ('__weakref__',)}),
    make('B', (EmptyTuple,), {'__slots__': ('__weakref__',)}),
    make('B', (Plain,), {'__slots__': ('__dict__',)}),
    make('B', (object,), {'__slots__': ('1a',)}),
    make('B', (object,), {'__slots__': ('a-b',)}),
    make('B', (object,), {'__slots__': ('',)}),
    make('B', (object,), {'__slots__': (1,)}),
    make('B', (object,), {'__slots__': 5}),
    make('B', (object,), {'__slots__': None}),
    make('B', (object,), {'__slots__': (u'\xe9',)}),
    make('B', (tuple,), {'__slots__': ('a',)}),
    make('B', (str,), {'__slots__': ('a',)}),
    make('B', (long,), {'__slots__': ('a',)}),
    make('B', (tuple,), {'__slots__': ('__dict__',)}),
    make('B', (int,), {'__slots__': ('a',)}),
    make('B', (Classic,), {'__slots__': ('a',)}),
]

names = [
    make('B', (object,), {'__slots__': 'abc'}),
    make('B', (object,), {'__slots__': u'abc'}),
    make('B', (object,), {'__slots__': (u'abc', 'b')}),
    make('B', (object,), {'__slots__': ('a',), 'a': 1}),
    make('_Under', (object,), {'__slots__': ('__x', '__y__', '_z')}),
    make('__', (object,), {'__slots__': ('__x',)}),
    make('B', (object,), {'__slots__': ('__dict__', '__weakref__', 'c')}),
    make('B', (tuple,), {'__slots__': ()}),
    make('B', (int,), {}),
    make('B', (Slotted,), {'__slots__': ('x',)}),
]

layouts = [
    make('C', (Slotted, Other), {}),
    make('C', (Slotted, Nothing), {}),
    make('C', (Nothing, Slotted), {}),
    make('C', (Slotted, int), {}),
    make('C', (Slotted, dict), {}),
    make('C', (Slotted, object), {}),
    make('C', (Slotted, Plain), {}),
    make('C', (Plain, Slotted), {}),
    make('C', (Slotted, Classic), {'__slots__': ()}),
    make('C', (Slotted, WeakOnly), {'__slots__': ()}),
    make('C', (WeakOnly, DictOnly), {}),
    make('C', (Tuple1, Tuple2), {}),
    make('C', (EmptyTuple, Tuple1), {}),
    make('C', (int, str), {}),
    make('C', (list, dict), {}),
    make('C', (KeyError, ValueError), {}),
    make('C', (Classic,), {'__metaclass__': type}),
    make('C', (bool,), {}),
]

RESULT = (errors, names, layouts)
