# __class__ and __bases__ assignment require matching instance layouts
# (compatible_for_assignment).


def assign_class(instance, cls):
    try:
        instance.__class__ = cls
    except Exception as error:
        return (type(error).__name__, str(error))
    return type(instance).__name__


def set_bases(cls, bases):
    try:
        cls.__bases__ = bases
    except Exception as error:
        return (type(error).__name__, str(error))
    return [c.__name__ for c in cls.__mro__]


class AB(object):
    __slots__ = ('a', 'b')


class BA(object):
    __slots__ = ('b', 'a')


class AC(object):
    __slots__ = ('a', 'c')


class A(object):
    __slots__ = ('a',)


class Plain1(object):
    pass


class Plain2(object):
    pass


class Plain3(Plain1):
    pass


class DictOnly(object):
    __slots__ = ('__dict__',)


class WeakOnly(object):
    __slots__ = ('__weakref__',)


class DictWeak(object):
    __slots__ = ('__dict__', '__weakref__')


class Empty1(object):
    __slots__ = ()


class Empty2(object):
    __slots__ = []


class Int1(int):
    pass


class Int2(int):
    __slots__ = ()


class Int3(int):
    __slots__ = ()


class List1(list):
    pass


class X1(object):
    __slots__ = ('x',)


class X2(X1):
    pass


class X3(X1):
    pass


slotted = AB()
slotted.a = 1
classes = [
    assign_class(slotted, BA),
    (slotted.a, getattr(slotted, 'b', '<unset>')),
    assign_class(slotted, AC),
    assign_class(slotted, A),
    assign_class(slotted, Plain1),
    assign_class(Plain1(), Plain2),
    assign_class(Plain1(), Plain3),
    assign_class(Plain3(), Plain2),
    assign_class(Plain1(), DictWeak),
    assign_class(Plain1(), DictOnly),
    assign_class(DictOnly(), WeakOnly),
    assign_class(Empty1(), Empty2),
    assign_class(Empty1(), Plain1),
    assign_class(Empty1(), object),
    assign_class(object(), Empty1),
    assign_class(Int2(1), Int3),
    assign_class(Int1(1), Int3),
    assign_class(Int2(1), int),
    assign_class(List1(), Plain1),
    assign_class(Plain1(), 1),
    assign_class(X2(), X3),
    assign_class(X2(), X1),
]
try:
    del Plain1().__class__
except TypeError as error:
    classes.append(str(error))


class Y1(object):
    __slots__ = ('y',)


class Y2(Y1):
    pass


class Y3(object):
    pass


class Y4(object):
    pass


class Y5(Y3):
    pass


bases = [
    set_bases(Y2, (Y3,)),
    set_bases(Y3, (Y4,)),
    set_bases(Y3, (Y1,)),
    set_bases(Y2, (A,)),
    set_bases(Y5, (Y4,)),
    set_bases(Y5, (Y3,)),
]

RESULT = (classes, bases)
