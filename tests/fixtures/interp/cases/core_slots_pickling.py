# object.__reduce_ex__ collects __slots__ values into the state, protocols
# below 2 refuse slotted classes without __getstate__, and copy and cPickle
# restore the slots with setattr.
import copy
import copy_reg
import cPickle
import imp
import pickle
import sys

# Pickles name classes by module; the reference runs cases outside
# sys.modules, so the classes are published under a registered module.
HOST = imp.new_module('slots_pickling_host')
sys.modules['slots_pickling_host'] = HOST


def attempt(function):
    try:
        return ('ok', function())
    except Exception as error:
        return (type(error).__name__, str(error))


class Point(object):
    __slots__ = ('x', 'y')


class Private(object):
    __slots__ = ('__x', '_y', '__z__')

    def fill(self):
        self.__x = 1
        self._y = 2
        self.__z__ = 3


class Mixed(object):
    __slots__ = ('a', 'b', '__dict__')

    def __init__(self):
        self.a = [1]
        self.x = 2


class Child(Point):
    __slots__ = ('z',)


class Opened(Point):
    pass


class Duplicate(object):
    __slots__ = ('a', 'a')


class Stateful(object):
    __slots__ = ('a',)

    def __getstate__(self):
        return {'a': self.a}

    def __setstate__(self, state):
        self.a = state['a'] * 2


class _Hidden(object):
    __slots__ = ('__x', '_y')

    def fill(self):
        self.__x = 1
        self._y = 2


class __Dunder(object):
    __slots__ = ('__x',)


for _class in (Point, Private, Mixed, Child, Opened, Duplicate, Stateful, _Hidden, __Dunder):
    _class.__module__ = HOST.__name__
    setattr(HOST, _class.__name__, _class)

point = Point()
point.x = 5
private = Private()
private.fill()
mixed = Mixed()
child = Child()
child.x = 1
child.z = 2
opened = Opened()
opened.y = 3
opened.q = 4
duplicate = Duplicate()
duplicate.a = 1
stateful = Stateful()
stateful.a = 4
hidden = _Hidden()
hidden.fill()

reduced = [
    attempt(lambda: point.__reduce_ex__(0)),
    attempt(lambda: point.__reduce_ex__(1)),
    attempt(lambda: point.__reduce_ex__(2)[1:]),
    attempt(lambda: Point().__reduce_ex__(2)[1:]),
    attempt(lambda: private.__reduce_ex__(2)[2]),
    attempt(lambda: mixed.__reduce_ex__(2)[2]),
    attempt(lambda: child.__reduce_ex__(2)[2]),
    attempt(lambda: opened.__reduce_ex__(2)[2]),
    attempt(lambda: opened.__reduce_ex__(1)),
    attempt(lambda: duplicate.__reduce_ex__(2)[2]),
    attempt(lambda: stateful.__reduce_ex__(2)[2]),
    attempt(lambda: hidden.__reduce_ex__(2)[2]),
]

names = [
    copy_reg._slotnames(Point),
    Point.__dict__.get('__slotnames__'),
    copy_reg._slotnames(Private),
    copy_reg._slotnames(Child),
    copy_reg._slotnames(Opened),
    copy_reg._slotnames(Duplicate),
    copy_reg._slotnames(_Hidden),
    copy_reg._slotnames(__Dunder),
]

copied = copy.copy(mixed)
deep = copy.deepcopy(mixed)
point_copy = copy.copy(point)
copies = [
    (copied.a is mixed.a, copied.x, getattr(copied, 'b', '<unset>'), copied.__dict__),
    (deep.a is mixed.a, deep.a, deep.x, deep.__dict__),
    (point_copy.x, getattr(point_copy, 'y', '<unset>')),
    attempt(lambda: point_copy.__dict__),
    copy.deepcopy(child).z,
    copy.copy(stateful).a,
]

pickled = []
for protocol in (0, 1, 2):
    pickled.append(attempt(lambda: cPickle.dumps(point, protocol)))
    pickled.append(attempt(lambda: pickle.dumps(point, protocol)))
for protocol in (0, 2):
    pickled.append(cPickle.loads(cPickle.dumps(stateful, protocol)).a)
loaded = cPickle.loads(cPickle.dumps(point, 2))
pickled.append((type(loaded).__name__, loaded.x, getattr(loaded, 'y', '<unset>')))
pickled.append(attempt(lambda: loaded.__dict__))
loaded = cPickle.loads(cPickle.dumps(mixed, 2))
pickled.append((loaded.a, loaded.x, loaded.__dict__))
loaded = pickle.loads(pickle.dumps(opened, 2))
pickled.append((loaded.y, loaded.__dict__))
loaded = cPickle.loads(cPickle.dumps(private, 2))
pickled.append((loaded._Private__x, loaded._y, loaded.__z__))

RESULT = (reduced, names, copies, pickled)
