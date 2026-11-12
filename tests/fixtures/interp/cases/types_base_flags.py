import array
import cStringIO
import collections
import functools
import imp
import itertools
import operator
import re
import _struct as struct
import sys
import thread
import time
import types
import weakref

def derive(base):
    try:
        type('Derived', (base,), {})
        return (base.__name__, 'ok')
    except TypeError as e:
        return (base.__name__, str(e))

def generator():
    yield 1

class Classic:
    def method(self):
        pass

class New(object):
    __slots__ = ('slot',)

def cell_type():
    value = 1
    def inner():
        return value
    return type(inner.func_closure[0])

pattern = re.compile('a')
finals = [
    bool, type(None), type(NotImplemented), type(Ellipsis), slice,
    types.FunctionType, types.BuiltinFunctionType, types.MethodType,
    types.CodeType, types.FrameType, types.GeneratorType, cell_type(),
    buffer, xrange, memoryview, types.ClassType, types.InstanceType,
    types.DictProxyType, types.GetSetDescriptorType, types.MemberDescriptorType,
    types.TracebackType, type(iter('')), type({}.viewkeys()),
    type({}.viewvalues()), type({}.viewitems()), type(iter(collections.deque())),
    type(reversed(collections.deque())), type(iter(array.array('b'))),
    type(pattern), type(pattern.match('a')), type(pattern.scanner('a')),
    type(cStringIO.StringIO()), type(cStringIO.StringIO('a')),
    type(thread.allocate_lock()), operator.itemgetter, operator.attrgetter,
    operator.methodcaller, weakref.ProxyType, weakref.CallableProxyType,
    type(itertools.tee([])[0]), type(next(itertools.groupby('a'))[1]), imp.NullImporter,
    time.struct_time, type(sys.version_info), type(New.slot),
]
bases = [
    object, int, long, float, complex, str, unicode, basestring, tuple, list,
    dict, set, frozenset, bytearray, type, property, staticmethod, classmethod,
    super, enumerate, reversed, file, types.ModuleType, Exception,
    UnicodeDecodeError, array.array, collections.deque, collections.defaultdict,
    functools.partial, struct.Struct, thread._local, weakref.ref,
    itertools.count, itertools.chain, itertools.groupby, itertools.izip_longest,
]

def mixed():
    try:
        class Derived(Classic, object, bool):
            pass
    except TypeError as e:
        return str(e)

RESULT = ([derive(base) for base in finals], [derive(base) for base in bases], mixed())
