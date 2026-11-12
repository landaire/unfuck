# cPickle writes a PUT for a string, tuple, or reduced object only when it
# has more than one reference, so these depend on CPython's reference counts
# for temporaries, call arguments, locals, cells, and container items.
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


def dumps(value):
    return cPickle.dumps(value, 2)


def through_local(value):
    return cPickle.dumps(value, 2)


def through_two_locals(value):
    other = value
    return cPickle.dumps(other, 2)


def through_cell(value):
    def inner():
        return cPickle.dumps(value, 2)
    return inner()


def through_star(*args):
    return cPickle.dumps(args[0], 2)


def through_kwargs(**kwargs):
    return cPickle.dumps(kwargs['v'], 2)


def returns_temporary():
    return K('r') + K('s')


@export
class Reduced(object):
    def __reduce__(self):
        return (tuple, ((K('p') + K('q'), K('lit')),))


@export
class Holder(object):
    def __init__(self):
        self.attr = K('h') + K('i')


RESULT = []
RESULT.append(cPickle.dumps(K('a') + K('b'), 2))
RESULT.append(cPickle.dumps(K('lit'), 2))
x = K('c') + K('d')
RESULT.append(cPickle.dumps(x, 2))
RESULT.append(cPickle.dumps([x, x], 2))
RESULT.append(cPickle.dumps([K('e') + K('f')], 2))
RESULT.append(cPickle.dumps((K('e') + K('f'),), 2))
RESULT.append(cPickle.dumps((K('e') + K('f'), x), 2))
RESULT.append(cPickle.dumps({K('k') + K('l'): K('m') + K('n')}, 2))
RESULT.append(cPickle.dumps(tuple([K(1), K(2)]), 2))
t = tuple([K(1), K(2)])
RESULT.append(cPickle.dumps(t, 2))
RESULT.append(cPickle.dumps((t, t), 2))
RESULT.append(dumps(K('g') + K('h')))
RESULT.append(through_local(K('g') + K('h')))
RESULT.append(through_two_locals(K('g') + K('h')))
RESULT.append(through_cell(K('g') + K('h')))
RESULT.append(through_star(K('g') + K('h')))
RESULT.append(through_kwargs(v=K('g') + K('h')))
RESULT.append(cPickle.dumps(returns_temporary(), 2))
RESULT.append(cPickle.dumps(Reduced(), 2))
RESULT.append(cPickle.dumps(Holder().attr, 2))
h = Holder()
RESULT.append(cPickle.dumps(h.attr, 2))
RESULT.append(cPickle.dumps(h, 2))
RESULT.append(cPickle.dumps([Holder()], 2))
RESULT.append(cPickle.dumps(obj=K('o') + K('p'), protocol=2))
RESULT.append(cPickle.dumps(*(K('o') + K('p'), 2)))
args = (K('o') + K('p'), 2)
RESULT.append(cPickle.dumps(*args))
RESULT.append(cPickle.dumps(str(K(12345)), 0))
RESULT.append(cPickle.dumps(unicode(K(12345)), 0))
RESULT.append([cPickle.dumps(K('u') + K('v'), 1) for i in range(2)])
RESULT.append(cPickle.dumps(K('w') * 3, 1) if K(True) else None)
RESULT.append(cPickle.dumps(K('lambda') + K('x'), 2))
RESULT.append((lambda v: cPickle.dumps(v, 2))(K('y') + K('z')))
for item in [K('a') + K('b')]:
    RESULT.append(cPickle.dumps(item, 2))
table = {K('k'): K('t') + K('u')}
RESULT.append(cPickle.dumps(table[K('k')], 2))
RESULT.append(cPickle.dumps(table.get(K('k')), 2))
RESULT.append(cPickle.dumps(getattr(h, 'attr'), 2))
RESULT.append(cPickle.dumps(K('') or K('m') + K('n'), 2))


def with_default(value=K('d') + K('e')):
    return cPickle.dumps(value, 2)


RESULT.append(with_default())
RESULT.append(with_default(K('d') + K('f')))
augmented = K('a')
augmented += K('g')
RESULT.append(cPickle.dumps(augmented, 2))
RESULT.append(list(cPickle.dumps(K('x') + K(str(i)), 2) for i in range(2)))


def generator():
    yield cPickle.dumps(K('q') + K('r'), 2)
    local = K('q') + K('s')
    yield cPickle.dumps(local, 2)


RESULT.append(list(generator()))
import cStringIO
stream = cStringIO.StringIO()
pickler = cPickle.Pickler(stream, 2)
pickler.dump(K('p') + K('d'))
pickler.dump(augmented)
pickler.dump((K('p') + K('e'), K(1)))
RESULT.append(stream.getvalue())
stream = cStringIO.StringIO()
cPickle.dump(K('c') + K('d'), stream, 2)
cPickle.dump((augmented,), stream, 2)
RESULT.append(stream.getvalue())
list_pickler = cPickle.Pickler(2)
list_pickler.dump([K('l') + K('p'), (K('l') + K('q'),)])
RESULT.append(list_pickler.getvalue())
