# Errors raised while pickling.
import cPickle
import copy_reg
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


def K(x):
    return x


def attempt(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception as e:
        return (type(e).__name__, re.sub(' at 0x[0-9a-fA-F]+', '', str(e)))


@export
def nested():
    def inner():
        pass
    inner.__module__ = 'cpickle_case_helpers'
    return inner


@export
class Bad1(object):
    pass


def reduce_bad1(obj):
    return K(5)


copy_reg.pickle(Bad1, reduce_bad1)


@export
class Bad2(object):
    pass


def reduce_bad2(obj):
    return (K(1),)


copy_reg.pickle(Bad2, reduce_bad2)


@export
class Bad3(object):
    pass


def reduce_bad3(obj):
    return (len, K(5))


copy_reg.pickle(Bad3, reduce_bad3)


@export
class Bad4(object):
    pass


def reduce_bad4(obj):
    return (len, (), None, K(5))


copy_reg.pickle(Bad4, reduce_bad4)


@export
class Bad5(object):
    pass


def reduce_bad5(obj):
    return (len, (), None, None, [K(1)])


copy_reg.pickle(Bad5, reduce_bad5)


@export
class Bad6(object):
    pass


def reduce_bad6(obj):
    return (len, (), None, None, None, None)


copy_reg.pickle(Bad6, reduce_bad6)


@export
def __newobj__(cls, *args):
    return cls


@export
class Bad7(object):
    def __reduce__(self):
        return (__newobj__, ())


@export
class Bad8(object):
    def __reduce__(self):
        return (__newobj__, (K(5),))


@export
class Bad9(object):
    def __reduce__(self):
        return (__newobj__, (Bad1,))


@export
class Raises(object):
    def __reduce_ex__(self, protocol):
        raise ValueError('nope %d' % protocol)


@export
class Renamed(object):
    pass


Renamed.__name__ = 'NotThere'


@export
def lam():
    pass


other = lam
HELPERS.lam = None
anonymous = lambda: 0
anonymous.__module__ = 'cpickle_case_helpers'


@export
class Pairs(dict):
    def iteritems(self):
        return iter([K(1)])


RESULT = []
for protocol in (0, 1, 2):
    for value in [Bad1(), Bad2(), Bad3(), Bad4(), Bad5(), Bad6(), Bad7(), Bad8(), Bad9(), Raises(), Renamed]:
        RESULT.append(attempt(cPickle.dumps, value, protocol))
# A function that is not reachable by name falls back to its reduction. At
# protocols 1 and 2 that pickles the `function` type by reference, which
# depends on `function.__module__`; only protocol 0 is checked here.
for value in [nested(), other, anonymous]:
    RESULT.append(attempt(cPickle.dumps, value, 0))
RESULT.append(attempt(cPickle.dumps, K(1), 3))
RESULT.append(attempt(cPickle.dumps))
RESULT.append(attempt(cPickle.dumps, K(1), 'x'))
RESULT.append(attempt(cPickle.dumps, K(1), 1.5))
RESULT.append(attempt(cPickle.dumps, K(1), 1, 2))
RESULT.append(attempt(cPickle.dumps, K(1), protocol=1, bogus=2))
RESULT.append(attempt(cPickle.dump, K(1)))
RESULT.append(attempt(cPickle.dump, K(1), K(5)))
RESULT.append(attempt(cPickle.Pickler, K(5), 1, 2))
RESULT.append(attempt(cPickle.Pickler, 1.5))
RESULT.append(attempt(cPickle.Pickler, K(object())))
e = cPickle.UnpickleableError(K(5))
RESULT.append((str(e), str(cPickle.UnpickleableError()), str(cPickle.PickleError('m')), str(cPickle.PickleError())))
RESULT.append([c.__name__ for c in cPickle.UnpickleableError.__mro__])
RESULT.append([c.__name__ for c in cPickle.BadPickleGet.__mro__])
RESULT.append((cPickle.PicklingError.__module__, cPickle.HIGHEST_PROTOCOL, cPickle.format_version, cPickle.compatible_formats, cPickle.__version__))
deep = []
for i in range(2000):
    deep = [deep]
RESULT.append(attempt(cPickle.dumps, deep, 2))
