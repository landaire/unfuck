# parser.st attribute lookup goes through parser_getattr (Py_FindMethod):
# only the methods, __methods__, and __doc__ exist on a tree, and a missing
# name raises AttributeError(name). Assignment fails as for a type without
# tp_setattr until a lookup on the type readies it (initparser never calls
# PyType_Ready). Comparisons use parser_compare only for two trees;
# __cmp__ itself rejects other operands. dir() does not ready the type.
import copy
import parser


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)


def assign(target, name, value):
    setattr(target, name, value)


def remove(target, name):
    delattr(target, name)


class Classic:
    def __cmp__(self, other):
        return -1


class Ordered(object):
    def __cmp__(self, other):
        return 1


a = parser.expr(K('a'))
b = parser.expr(K('b'))
a2 = parser.expr(K('a'))

unready = (
    err(object.__setattr__, a, 'x', 1), err(object.__delattr__, a, 'x'),
    err(assign, a, 'x', 1), err(assign, a, 'compile', 1), err(remove, a, 'x'),
    err(getattr, a, 'foo'), err(getattr, a, '__class__'), err(getattr, a, '__dict__'),
    err(getattr, a, '__cmp__'), err(getattr, a, '__repr__'), err(getattr, a, '__hash__'),
    err(lambda: a.nonexistent), getattr(a, 'zz', 5), hasattr(a, 'compile'), hasattr(a, '__class__'),
    hasattr(a, 'totuple\0x'), err(getattr, a, 'nope\0more'),
    a.__methods__, callable(a.compile), a.isexpr(), a.__sizeof__(),
    a.totuple() == getattr(a, 'totuple')(), eval(a.compile(), {'a': 7}),
    isinstance(a, parser.STType), type(a) is parser.STType, isinstance(a, int),
    a == a2, a != b, a < b, cmp(a, b), cmp(b, a), cmp(a, a2),
    a == None, a != None, a > None, cmp(a, None), cmp(None, a), a == 1, a < 1, cmp(a, 1), cmp(1, a),
    a == 'x', cmp(a, 'x'), cmp(a, ()), cmp(a, []), cmp(a, {}),
    cmp(a, Classic()), cmp(Classic(), a), cmp(a, Ordered()), cmp(Ordered(), a),
    [a] == [a2], a in [b, a2], [x.totuple() for x in sorted([b, a])],
    err(assign, a, 'x', 1),
)

after_dir = (dir(a), err(assign, a, 'x', 1), err(assign, a, 'compile', 1), err(remove, a, 'x'))

# PyObject_GenericGetAttr readies the type.
generic = (
    err(object.__getattribute__, a, 'zz'), err(assign, a, 'x', 1),
    err(object.__setattr__, a, 'x', 1), err(object.__setattr__, a, 'compile', 1), err(object.__delattr__, a, 'x'),
    callable(object.__getattribute__(a, 'compile')), object.__getattribute__(a, '__class__') is parser.STType,
)

ready = (
    err(hash, a), err(assign, a, 'x', 1), err(assign, a, 'compile', 1), err(remove, a, 'x'), err(remove, a, 'compile'),
    dir(a), err(parser.STType.__cmp__, a, a2), err(parser.STType.__cmp__, a, b), err(parser.STType.__cmp__, b, a),
    err(parser.STType.__cmp__, a, 5), err(parser.STType.__cmp__, a, None), err(parser.STType.__cmp__, a, Classic()),
    err(parser.STType.__cmp__, 5, a), err(parser.STType.__cmp__, a),
    copy.copy(a) == a, type(a).__name__,
)

RESULT = (unready, after_dir, generic, ready)
