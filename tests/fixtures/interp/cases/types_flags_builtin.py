import _io
import _socket
import _ssl
import array
import collections
import cStringIO
import datetime
import functools
import itertools
import mmap
import operator
import pyexpat
import re
import struct
import sys
import thread
import types
import unicodedata
import weakref

def K(value):
    return value

def generator():
    yield 1

def cell():
    value = 1
    return (lambda: value).func_closure[0]

pattern = re.compile(K('a'))
candidates = [
    object, type, int, long, bool, float, complex, str, unicode, basestring, bytearray, tuple, list,
    dict, set, frozenset, slice, xrange, buffer, memoryview, property, staticmethod, classmethod,
    super, enumerate, reversed, file, type(None), type(NotImplemented), type(Ellipsis),
    types.FunctionType, types.BuiltinFunctionType, types.MethodType, types.CodeType, types.FrameType,
    types.GeneratorType, types.TracebackType, types.ClassType, types.InstanceType, types.ModuleType,
    types.DictProxyType, types.GetSetDescriptorType, types.MemberDescriptorType, type(cell()),
    type(iter('')), type(iter([])), type(reversed([])), type(iter(())), type(iter(bytearray())),
    type(iter(xrange(1))), type(iter(set())), type({}.iterkeys()), type({}.itervalues()),
    type({}.iteritems()), type(iter(lambda: 1, 2)), type({}.viewkeys()), type({}.viewvalues()),
    type({}.viewitems()), BaseException, Exception, StandardError, ValueError, KeyError,
    UnicodeDecodeError, StopIteration, SystemExit, KeyboardInterrupt, Warning, UserWarning,
    weakref.ref, weakref.ProxyType, weakref.CallableProxyType, thread._local, thread.LockType,
    type(pattern), type(pattern.match('a')), type(pattern.scanner('a')), type(sys.version_info),
    itertools.chain, itertools.count, collections.deque, collections.defaultdict, functools.partial,
    operator.itemgetter, array.array, datetime.datetime, datetime.timedelta, type(cStringIO.StringIO()),
    type(cStringIO.StringIO('x')), _io.BytesIO, _io.FileIO, _io.TextIOWrapper, struct.Struct,
    _socket.socket, _ssl._SSLContext, mmap.mmap, pyexpat.XMLParserType, unicodedata.UCD,
]

def touched_flags(cls):
    # The attribute lookup on the class sets Py_TPFLAGS_VALID_VERSION_TAG
    # whenever the class can use the method cache.
    getattr(cls, K('missing_attribute'), None)
    return cls.__flags__

RESULT = [(cls.__name__, touched_flags(cls)) for cls in candidates]
