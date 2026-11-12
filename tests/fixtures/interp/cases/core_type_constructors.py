import new
import types

RESULT = []


def show(*values):
    RESULT.append(' '.join(str(value) for value in values))


def attempt(label, function, *args, **kwargs):
    try:
        result = function(*args, **kwargs)
    except Exception as error:
        show(label, type(error).__name__, error)
        return None
    show(label, 'ok')
    return result


class S(str):
    pass


def outer():
    value = 1

    def inner(a, b=2):
        return a + b + value
    return inner


inner = outer()
code = inner.func_code
cell = inner.func_closure[0]


def plain(a, b=5):
    return a * b


F = types.FunctionType
show(F is new.function, types.CodeType is new.code, types.ClassType is new.classobj)
show(types.InstanceType is new.instance, types.ModuleType is new.module)
show(types.MethodType is new.instancemethod)
show(sorted(name for name in dir(new) if not name.startswith('__')))

f = F(plain.func_code, globals())
show(f.__name__, f(3, 1), f.func_defaults, f.func_closure, f.__module__)
f = F(plain.func_code, globals(), 'renamed', (7,))
show(f.__name__, f(3), f.func_defaults)
f = F(plain.func_code, {'__name__': 'elsewhere'}, None, None, None)
show(f.__name__, f.__module__, f.func_defaults)
f = F(code=plain.func_code, globals={}, name=S('sub'))
show(f.__name__, f.__module__)
f = F(code, globals(), None, (4,), (cell,))
show(f(1), f.func_closure[0] is cell)
attempt('no args', F)
attempt('one arg', F, plain.func_code)
attempt('bad code', F, 1, {})
attempt('bad globals', F, plain.func_code, [])
attempt('bad name', F, plain.func_code, {}, 5)
attempt('unicode name', F, plain.func_code, {}, u'x')
attempt('bad defaults', F, plain.func_code, {}, None, [1])
attempt('closure needed', F, code, {})
attempt('closure none', F, code, {}, None, None, None)
attempt('closure list', F, code, {}, None, None, [cell])
attempt('closure list plain', F, plain.func_code, {}, None, None, [cell])
attempt('closure short', F, code, {}, None, None, ())
attempt('closure long', F, plain.func_code, {}, None, None, (cell,))
attempt('closure type', F, code, {}, None, None, (1,))
attempt('too many', F, plain.func_code, {}, None, None, None, None)
attempt('keyword', F, plain.func_code, {}, bogus=1)

C = types.CodeType
c = plain.func_code
args = [c.co_argcount, c.co_nlocals, c.co_stacksize, c.co_flags, c.co_code, c.co_consts, c.co_names, c.co_varnames, c.co_filename, c.co_name, c.co_firstlineno, c.co_lnotab]
c2 = C(*args)
show(c2.co_name, c2.co_varnames, c2.co_freevars, c2.co_cellvars, c2.co_code == c.co_code, c2.co_consts == c.co_consts)
show(F(c2, {})(2, 3))
c3 = C(*(args + [('v',), ('w',)]))
show(c3.co_freevars, c3.co_cellvars)


def replace(index, value):
    changed = list(args)
    changed[index] = value
    return changed


attempt('code no args', C)
attempt('code eleven', C, *args[:11])
attempt('code keyword', C, *args, freevars=())
attempt('code argcount', C, *replace(0, -1))
attempt('code nlocals', C, *replace(1, -1))
attempt('code argcount type', C, *replace(0, 'x'))
attempt('code argcount float', C, *replace(0, 1.5))
attempt('code bytes', C, *replace(4, u'x'))
attempt('code bytes list', C, *replace(4, [1]))
attempt('code consts', C, *replace(5, [None]))
attempt('code names', C, *replace(6, [1]))
attempt('code names item', C, *replace(6, (1,)))
attempt('code varnames item', C, *replace(7, ('a', u'b')))
attempt('code filename', C, *replace(8, None))
attempt('code name', C, *replace(9, u'n'))
attempt('code lineno', C, *replace(10, 'x'))
attempt('code lnotab', C, *replace(11, None))
attempt('code freevars', C, *(args + [['v']]))
attempt('code cellvars item', C, *(args + [(), (3,)]))
attempt('code fifteen', C, *(args + [(), (), ()]))
dynamic = 'dyn' + 'amic'
sub = C(*replace(7, (S('a'), S('b'))))
show([type(name).__name__ for name in sub.co_varnames])
interned = C(*replace(6, (dynamic,)))
show(interned.co_names[0] is 'dynamic')
consts = C(*replace(5, (None, 'ab' + 'cd', 'not name' + '!')))
show(consts.co_consts[1] is 'abcd', consts.co_consts[2] is 'not name!')
show(C(*replace(9, S('subname'))).co_name)

K = types.ClassType
k = K('Made', (), {})
show(k.__name__, k.__module__, k.__doc__, k.__bases__)
k2 = K(name='Kw', bases=(k,), dict={'__doc__': 'doc', '__module__': 'm'})
show(k2.__name__, k2.__module__, k2.__doc__, k2.__bases__ == (k,))
k3 = K(S('Sub'), (), {})
show(k3.__name__)
attempt('class no args', K)
attempt('class name', K, 1, (), {})
attempt('class unicode', K, u'x', (), {})
attempt('class bases', K, 'x', [], {})
attempt('class base item', K, 'x', (1,), {})
attempt('class dict', K, 'x', (), [])
attempt('class many', K, 'x', (), {}, 1)

I = types.InstanceType
i = I(k)
show(type(i) is I, i.__class__ is k, i.__dict__)
d = {'a': 1}
i = I(k, d)
show(i.a, i.__dict__ is d)
i = I(k, None)
show(i.__dict__)
attempt('instance no args', I)
attempt('instance class', I, object)
attempt('instance dict', I, k, [])
attempt('instance keyword', I, k, dict={})
attempt('instance many', I, k, {}, 1)

M = types.ModuleType
m = M('mod')
show(m.__name__, m.__doc__, repr(m))
m = M('mod', 'doc')
show(m.__doc__)
m = M(name='kw', doc=5)
show(m.__name__, m.__doc__)
m = M(S('subm'))
show(type(m.__name__).__name__)
attempt('module no args', M)
attempt('module name', M, 1)
attempt('module unicode', M, u'x')
attempt('module many', M, 'a', 'b', 'c')
attempt('module keyword', M, 'a', bogus=1)


# setattr with a str subclass name keys the dict by that instance.
class New(object):
    pass


class Classic:
    pass


for owner in (New(), Classic(), plain, types.ModuleType('host'), Classic):
    name = S('sub' + 'name')
    setattr(owner, name, 1)
    keys = [key for key in vars(owner) if key == 'subname']
    show(type(keys[0]).__name__, keys[0] is name, getattr(owner, 'subname'))
existing = New()
first = S('kept')
existing.__dict__[first] = 1
setattr(existing, S('kept'), 2)
show(list(existing.__dict__)[0] is first, existing.kept)
plain_name = New()
setattr(plain_name, u'uni', 1)
show([type(key).__name__ for key in plain_name.__dict__])

# str.__add__ with a unicode operand is PyUnicode_Concat.
text = u'abc'
empty = u''


class U(unicode):
    pass


for left, right in [('', text), ('xy', empty), ('', empty), ('xy', text), ('', U(u'q'))]:
    result = str.__add__(left, right)
    show(repr(result), type(result).__name__, result is right)
show(('' + text) is text, ('xy' + empty) is empty)
attempt('add int', str.__add__, '', 1)
show(repr(str.__add__('', bytearray('z'))))

# func_new keeps an empty argdefs tuple.
show(F(plain.func_code, {}, None, ()).func_defaults)

# code_richcompare and code_hash.
same = C(*args)
show(same == c, same != c, hash(same) == hash(c), same is c)
show(C(*replace(9, 'other')) == c, C(*replace(10, 99)) != c)
show(C(*replace(5, (None, 0))) == C(*replace(5, (None, 0.0))), C(*replace(5, (0.0,))) == C(*replace(5, (-0.0,))))
show(C(*replace(5, (1j,))) == C(*replace(5, (1j,))), C(*replace(5, ((1, 2),))) == C(*replace(5, ((1, 2),))))
show(C(*replace(5, (frozenset([1]),))) == C(*replace(5, (frozenset([1]),))), C(*replace(5, ([],))) == C(*replace(5, ([],))))
show(C(*replace(11, 'different lnotab')) == c, C(*replace(8, 'other.py')) == c)
show(len(set([same, c])), c == 1, c != 'x')

# Attribute lookups probe dicts with a str subclass name, so a custom hash
# round-trips.
class Hashed(str):
    def __hash__(self):
        return 7

    def __eq__(self, other):
        return str.__eq__(self, other)


for owner in (New(), Classic(), types.ModuleType('hashed')):
    setattr(owner, Hashed('hh'), 1)
    show(getattr(owner, Hashed('hh'), 'missing'), hasattr(owner, Hashed('hh')), getattr(owner, 'hh', 'missing'))
    delattr(owner, Hashed('hh'))
    show(len([key for key in vars(owner) if key == 'hh']))

# An explicit empty closure is kept.
show(F(plain.func_code, {}, None, None, ()).func_closure, F(plain.func_code, {}).func_closure)

# ModuleType.__new__ leaves the dict absent until a store or __init__.
bare = M.__new__(M)
show(bare.__dict__, vars(bare), repr(bare))
attempt('bare getattr', getattr, bare, 'anything')
attempt('bare delattr', delattr, bare, 'anything')
attempt('bare dir', dir, bare)
show(bare.__dict__)
bare.x = 1
show(sorted(bare.__dict__))
bare = M.__new__(M)
bare.__init__('z')
show(sorted(bare.__dict__.items()))
attempt('init receiver', M.__init__, 1, 'x')
attempt('init no receiver', M.__init__)
