# cPickle.dumps of classic and new-style instances, globals, and the
# __reduce__ family.
import cPickle
import imp
import re
import sys

# Globals pickle by module and name. The case module is not importable
# when the reference runs it, so the classes live in a registered module.
HELPERS = imp.new_module('cpickle_case_helpers')
sys.modules['cpickle_case_helpers'] = HELPERS


def export(obj):
    obj.__module__ = 'cpickle_case_helpers'
    setattr(HELPERS, obj.__name__, obj)
    return obj

import copy_reg


def K(x):
    return x


def every(value):
    out = []
    for protocol in (0, 1, 2):
        try:
            out.append(cPickle.dumps(value, protocol))
        except Exception as e:
            out.append((type(e).__name__, re.sub(' at 0x[0-9a-fA-F]+', '', str(e))))
    return out


@export
class Classic:
    def __init__(self):
        self.a = K(1)


@export
class ClassicArgs:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __getinitargs__(self):
        return (self.x, self.y)


@export
class ClassicState:
    def __getstate__(self):
        return [K(1), K(2)]

    def __setstate__(self, state):
        pass


@export
class ClassicDictState:
    def __getstate__(self):
        return {K('s'): K(5)}


@export
class New(object):
    def __init__(self):
        self.b = K(2)


@export
class NewArgs(object):
    def __new__(cls, *args):
        return object.__new__(cls)

    def __getnewargs__(self):
        return (K(7), K('eight'))


@export
class NewSlots(object):
    __slots__ = ('p', 'q')

    def __getstate__(self):
        return (self.p, self.q)


@export
class ReduceString(object):
    def __reduce__(self):
        return 'REDUCED'


REDUCED = ReduceString()


@export
def build(*args):
    return args


@export
class Reduce2(object):
    def __reduce__(self):
        return (build, (K(1), K(2)))


@export
class Reduce3(object):
    def __reduce__(self):
        return (build, (), {K('x'): K(1)})


@export
class Reduce3List(object):
    def __reduce__(self):
        return (build, (), [K(1)])


@export
class Reduce5(object):
    def __reduce__(self):
        return (build, (), None, iter([K(1), K(2), K(3)]), iter([(K('k'), K('v'))]))


@export
class ReduceEx(object):
    def __reduce_ex__(self, protocol):
        return (build, (protocol,))


@export
class NewObj(object):
    def __reduce__(self):
        return (copy_reg.__newobj__, (NewObj, K(3)), None)


@export
class Point(tuple):
    pass


@export
class MyList(list):
    pass


@export
class MyDict(dict):
    pass


@export
class Recursive(object):
    def __init__(self):
        self.me = self


@export
def function():
    pass


ci = Classic()
VALUES = [
    Classic(), ClassicArgs(K(1), K('two')), ClassicState(), ClassicDictState(),
    New(), NewArgs(), REDUCED, Reduce2(), Reduce3(), Reduce3List(), Reduce5(), ReduceEx(), NewObj(),
    Point((K(1), K(2))), MyList([K(1), K(2)]), MyDict(a=K(1)),
    Recursive(), [ci, ci],
    Classic, New, function, len, cPickle.dumps, int, type, object, Point,
    copy_reg._reconstructor,
]
ns = NewSlots()
ns.p = K(1)
ns.q = K(2)
VALUES.append(ns)

RESULT = [every(value) for value in VALUES]

copy_reg.add_extension('native_cpickle_dump_objects', 'function', 200)
copy_reg.add_extension('native_cpickle_dump_objects', 'Classic', 300)
copy_reg.add_extension('native_cpickle_dump_objects', 'New', 70000)
RESULT.append(every([function, Classic, New, function]))
copy_reg.remove_extension('native_cpickle_dump_objects', 'function', 200)
copy_reg.remove_extension('native_cpickle_dump_objects', 'Classic', 300)
copy_reg.remove_extension('native_cpickle_dump_objects', 'New', 70000)
