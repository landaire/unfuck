# cPickle memoizes strings, tuples, and reduced objects only when another
# reference to them exists, so single-reference values get no PUT.
import cPickle
import imp
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


@export
class Fresh(object):
    def __reduce__(self):
        return (tuple, ([K(1)],), {K('k'): str(12345)})


@export
class State(object):
    def __getstate__(self):
        return {str(678): (str(99), str(99))}


@export
class Classic:
    def __getinitargs__(self):
        return (str(4321), K('lit'))


RESULT = []
for protocol in (0, 1, 2):
    RESULT.append(cPickle.dumps(tuple([K(1), K(2)]), protocol))
    RESULT.append(cPickle.dumps((tuple([K(1)]), (K(2), K(3))), protocol))
    RESULT.append(cPickle.dumps([str(10), str(11), K('lit'), K('lit')], protocol))
    RESULT.append(cPickle.dumps((str(10), K('xy')), protocol))
    RESULT.append(cPickle.dumps({str(10): str(11)}, protocol))
    RESULT.append(cPickle.dumps(dict((str(i), str(i + 50)) for i in range(3)), protocol))
    RESULT.append(cPickle.dumps(Fresh(), protocol))
    RESULT.append(cPickle.dumps(State(), protocol))
    RESULT.append(cPickle.dumps(Classic(), protocol))
    RESULT.append(cPickle.dumps(str(12345), protocol))
    x = str(12345)
    RESULT.append(cPickle.dumps(x, protocol))
    RESULT.append(cPickle.dumps(unicode(12345), protocol))
