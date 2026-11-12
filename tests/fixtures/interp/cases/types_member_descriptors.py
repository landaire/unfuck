import cStringIO
import collections
import functools
import _struct
import re
import sys
import types

def K(value):
    return value

def attempt(function, *args):
    try:
        return repr(function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))

def describe(owner, name):
    descriptor = owner.__dict__[name]
    return (repr(descriptor), type(descriptor).__name__, type(descriptor) is types.MemberDescriptorType)

def assign(target, name, value):
    setattr(target, name, value)
    return getattr(target, name)

pattern = re.compile('(a)')
match = pattern.match('a')
partial = functools.partial(len, 'ab')
factory = collections.defaultdict(list)
output = cStringIO.StringIO()

RESULT = [
    describe(type(pattern), 'pattern'),
    describe(type(pattern), 'groupindex'),
    describe(type(match), 'string'),
    describe(type(match), 'lastindex'),
    describe(type(pattern.scanner('a')), 'pattern'),
    describe(functools.partial, 'func'),
    describe(functools.partial, 'args'),
    describe(functools.partial, 'keywords'),
    describe(functools.partial, '__dict__'),
    describe(collections.defaultdict, 'default_factory'),
    describe(collections.deque, 'maxlen'),
    describe(types.TracebackType, 'tb_next'),
    describe(type(output), 'softspace'),
    describe(type(output), 'closed'),
    describe(type(cStringIO.StringIO('a')), 'closed'),
    attempt(assign, partial, 'func', len),
    attempt(delattr, partial, 'args'),
    attempt(assign, pattern, 'flags', 1),
    attempt(assign, match, 'pos', 1),
    attempt(assign, match, 'lastindex', 1),
    attempt(assign, collections.deque(), 'maxlen', 1),
    attempt(assign, factory, 'default_factory', dict),
    attempt(assign, output, 'softspace', 1),
    attempt(assign, output, 'closed', 1),
    attempt(type(pattern).__dict__['pattern'].__get__, match, type(match)),
    attempt(functools.partial.__dict__['func'].__get__, 1, int),
    attempt(type(output).__dict__['softspace'].__get__, 1, int),
    partial.func is len, partial.args,
    describe(float, 'real'), describe(int, 'denominator'), describe(long, 'imag'),
    describe(_struct.Struct, 'format'), describe(_struct.Struct, 'size'),
    attempt(float.__dict__['real'].__get__, True, float),
    attempt(int.__dict__['numerator'].__get__, True, int),
    attempt(int.__dict__['imag'].__get__, 2.5, int),
    attempt(long.__dict__['real'].__get__, 3, long),
    attempt(float.__dict__['imag'].__get__, 2.5, float),
    attempt(_struct.Struct.__dict__['size'].__get__, 1, _struct.Struct),
    attempt(assign, _struct.Struct('h'), 'size', 1),
    attempt(assign, 1.5, 'real', 1),
    attempt(assign, 1, 'real', 1),
    attempt(delattr, 1.5, 'real'),
    attempt(setattr, 1, 'bit_length', 1),
    attempt(setattr, 'x', 'foo', 1),
    attempt(delattr, 1, 'foo'),
    attempt(delattr, (), 'count'),
    (K(2).real, K(2).imag, K(5L).denominator, K(2.5).real, K(2.5).imag, True.numerator, _struct.Struct('hh').size),
]

import _io
import _md5
import _sha
import _sha256
import _sha512
import zipimport

def flags(base):
    try:
        type('Derived', (base,), {})
        return (base.__name__, 'ok')
    except TypeError as e:
        return (base.__name__, str(e))

hashes = [type(_md5.new()), type(_sha.new()), type(_sha256.sha224()), type(_sha256.sha256()), type(_sha512.sha384()), type(_sha512.sha512())]
RESULT.append([
    [describe(kind, name) for kind in hashes for name in ('digest_size', 'digestsize', 'block_size', 'name')],
    attempt(assign, _sha256.sha256(), 'digest_size', 1),
    attempt(assign, _md5.new(), 'digest_size', 1),
    [flags(kind) for kind in hashes],
    describe(_io.BufferedReader, 'raw'), describe(_io.BufferedWriter, 'raw'), describe(_io.BufferedRandom, 'raw'),
    describe(_io.BufferedReader, 'closed'), describe(_io.TextIOWrapper, 'encoding'),
    describe(_io.TextIOWrapper, 'buffer'), describe(_io.TextIOWrapper, 'line_buffering'),
    describe(_io.TextIOWrapper, 'errors'), describe(zipimport.zipimporter, 'archive'),
    describe(zipimport.zipimporter, '_files'), describe(complex, 'real'), describe(complex, 'imag'),
    attempt(assign, K(1j), 'real', 2.0),
    [flags(kind) for kind in (_io.BytesIO, _io.StringIO, _io.FileIO, _io.BufferedReader, _io.TextIOWrapper, _io.IncrementalNewlineDecoder, zipimport.zipimporter, complex, memoryview)],
])

import array
import time

def describe_descriptor(owner, name):
    descriptor = owner.__dict__[name]
    return (name, descriptor.__name__, descriptor.__objclass__ is owner)

class Slotted(object):
    __slots__ = ('slot', '__weakref__')

class Plain(object):
    pass

RESULT.append([
    describe_descriptor(_struct.Struct, 'format'), describe_descriptor(_struct.Struct, 'size'),
    describe_descriptor(int, 'real'), describe_descriptor(long, 'denominator'), describe_descriptor(float, 'imag'),
    describe_descriptor(array.array, 'typecode'), describe_descriptor(collections.deque, 'maxlen'),
    describe_descriptor(collections.defaultdict, 'default_factory'),
    describe_descriptor(functools.partial, 'keywords'), describe_descriptor(type(output), 'softspace'),
    describe_descriptor(type(output), 'closed'), describe_descriptor(type(pattern), 'flags'),
    describe_descriptor(type(match), 'lastindex'), describe_descriptor(Slotted, 'slot'),
    describe_descriptor(Slotted, '__weakref__'), describe_descriptor(Plain, '__dict__'),
    describe_descriptor(object, '__class__'), describe_descriptor(types.FunctionType, 'func_code'),
    describe_descriptor(time.struct_time, 'tm_year')[1:], describe(time.struct_time, 'tm_mon'),
    type(time.struct_time.__dict__['tm_year']) is types.MemberDescriptorType,
    attempt(time.struct_time.__dict__['tm_year'].__get__, (1, 2), tuple),
    attempt(time.struct_time.__dict__['tm_year'].__set__, time.localtime(0), 1),
    time.gmtime(0).tm_year,
    attempt(types.MemberDescriptorType.__dict__['__doc__'].__get__, 1, int),
    repr(types.GetSetDescriptorType.__dict__['__doc__']),
    repr(types.MemberDescriptorType.__dict__['__name__']),
])

RESULT.append([describe_descriptor(complex, 'real'), describe_descriptor(complex, 'imag'), describe_descriptor(_io.BufferedReader, 'raw'), describe_descriptor(zipimport.zipimporter, 'archive')])
