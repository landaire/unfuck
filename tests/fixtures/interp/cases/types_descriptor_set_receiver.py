import array
import cStringIO
import collections
import functools
import re
import _struct

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))

class Slotted(object):
    __slots__ = ('slot',)

class Plain(object):
    pass

class SlottedChild(Slotted):
    pass

def make_twin():
    class Slotted(object):
        __slots__ = ('slot',)
    return Slotted

Twin = make_twin()

class Classic:
    pass

def rebase():
    class Target(object):
        pass
    Target.__bases__ = (bool,)

pattern = re.compile('a')
match = pattern.match('a')
output = cStringIO.StringIO()

def set_with(owner, name, target, value):
    return owner.__dict__[name].__set__(target, value)

def delete_with(owner, name, target):
    return owner.__dict__[name].__delete__(target)

RESULT = [
    attempt(set_with, functools.partial, 'func', 1, len),
    attempt(set_with, functools.partial, 'func', functools.partial(len), len),
    attempt(delete_with, functools.partial, 'args', 'x'),
    attempt(set_with, type(pattern), 'flags', match, 1),
    attempt(set_with, type(pattern), 'flags', pattern, 1),
    attempt(set_with, type(match), 'lastindex', pattern, 1),
    attempt(set_with, type(match), 'lastindex', match, 1),
    attempt(set_with, collections.deque, 'maxlen', [], 1),
    attempt(set_with, collections.deque, 'maxlen', collections.deque(), 1),
    attempt(set_with, collections.defaultdict, 'default_factory', {}, list),
    attempt(set_with, array.array, 'typecode', 'x', 'b'),
    attempt(set_with, array.array, 'typecode', array.array('b'), 'b'),
    attempt(set_with, type(output), 'softspace', cStringIO.StringIO('a'), 1),
    attempt(set_with, type(output), 'closed', 1, 1),
    attempt(set_with, Slotted, 'slot', Plain(), 1),
    attempt(delete_with, Slotted, 'slot', 1),
    attempt(set_with, Plain, '__dict__', Slotted(), {}),
    attempt(set_with, Plain, '__weakref__', 1, None),
    attempt(set_with, Plain, '__weakref__', Plain(), None),
    attempt(set_with, _struct.Struct, 'format', _struct.Struct('h'), 'b'),
    attempt(delete_with, _struct.Struct, 'size', _struct.Struct('h')),
    attempt(set_with, object, '__class__', Classic(), Classic),
    attempt(set_with, Slotted, 'slot', SlottedChild(), 1),
    attempt(set_with, Slotted, 'slot', Twin(), 1),
    attempt(set_with, float, 'real', 1, 1),
    attempt(rebase),
]
