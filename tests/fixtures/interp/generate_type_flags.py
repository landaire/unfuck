# Records `__flags__` of every static type of CPython 2.7.12 for Windows x64
# for the table in src/interp/type_flags.rs and the test beside it.
#
#   winpy2712.sh generate_type_flags.py > win64_type_flags.json
#
# A type's flags are read when it first becomes reachable: at startup, right
# after importing the module defining it, or after creating an instance.
# Reading `T.__flags__` looks up the attribute on `type` only, so it leaves
# Py_TPFLAGS_VALID_VERSION_TAG of T as it was. "subclass" holds the flags of
# `type('X', (T,), {'__slots__': ()})` without that bit.

import sys

HEAPTYPE = 1 << 9
BASETYPE = 1 << 10
VALID_VERSION_TAG = 1 << 19

SUBCLASSES = type.__dict__['__subclasses__']

MODULES = [
    '_ast', '_bisect', '_codecs', '_codecs_cn', '_codecs_hk', '_codecs_iso2022', '_codecs_jp', '_codecs_kr',
    '_codecs_tw', '_collections', '_csv', '_functools', '_heapq', '_hotshot', '_io', '_json', '_locale',
    '_lsprof', '_md5', '_multibytecodec', '_random', '_sha', '_sha256', '_sha512', '_sre', '_struct',
    '_subprocess', '_symtable', '_warnings', '_weakref', '_winreg', 'array', 'audioop', 'binascii', 'cPickle',
    'cStringIO', 'cmath', 'datetime', 'errno', 'exceptions', 'future_builtins', 'gc', 'imageop', 'imp',
    'itertools', 'marshal', 'math', 'mmap', 'msvcrt', 'nt', 'operator', 'parser', 'signal', 'strop', 'sys',
    'thread', 'time', 'xxsubtype', 'zipimport', 'zlib',
    'bz2', 'pyexpat', 'select', 'unicodedata', 'winsound', '_bsddb', '_ctypes', '_elementtree', '_hashlib',
    '_msi', '_multiprocessing', '_socket', '_sqlite3', '_ssl',
]

seen = {}
order = []


def key(t):
    module = t.__module__
    if module == '__builtin__':
        return t.__name__
    return module + '.' + t.__name__


def record(t):
    if t in seen:
        return
    flags = t.__flags__
    seen[t] = flags
    global order
    order += [t]


def walk(t):
    if not (t.__flags__ & HEAPTYPE):
        record(t)
    for sub in SUBCLASSES(t):
        walk(sub)


def instance_factories():
    """Zero-argument callables, each creating an object whose type may only
    be reachable through an instance. A factory looks up attributes only on
    types that earlier factories or modules made reachable."""
    import _elementtree
    import _io
    import _subprocess
    import array
    import collections
    import cStringIO
    import itertools
    import re
    import thread

    def generator():
        yield 1

    def cell():
        value = 1
        return (lambda: value).func_closure[0]

    def traceback():
        try:
            raise ValueError
        except ValueError:
            return sys.exc_info()[2]

    return [
        lambda: iter([]), lambda: iter(()), lambda: iter(''), lambda: iter(u''), lambda: iter({}),
        lambda: iter(set()), lambda: iter(bytearray()), lambda: iter(xrange(1)), lambda: iter(lambda: 1, 2),
        lambda: reversed([]), lambda: reversed(xrange(1)), lambda: reversed('a'), lambda: {}.iterkeys(),
        lambda: {}.itervalues(), lambda: {}.iteritems(), lambda: {}.viewkeys(), lambda: {}.viewvalues(),
        lambda: {}.viewitems(), generator, cell, traceback, lambda: sys._getframe(), lambda: enumerate([]),
        lambda: memoryview(''), lambda: buffer(''), lambda: NotImplemented, lambda: Ellipsis, lambda: None,
        lambda: slice(1), lambda: property(), lambda: staticmethod(None), lambda: classmethod(None),
        lambda: super(object), lambda: (1).__add__, lambda: [].append, lambda: object.__init__,
        lambda: int.__add__, lambda: dict.fromkeys, lambda: type.__dict__['__flags__'],
        lambda: type.__dict__['__name__'], lambda: dict.__dict__, lambda: complex.real,
        lambda: iter(collections.deque()), lambda: reversed(collections.deque()),
        lambda: iter(array.array('b')), lambda: re.compile('a'), lambda: re.compile('a').match('a'),
        lambda: re.compile('a').scanner('a'), lambda: cStringIO.StringIO(), lambda: cStringIO.StringIO('a'),
        lambda: thread.allocate_lock(), lambda: itertools.tee([])[0], lambda: next(itertools.groupby('a'))[1],
        lambda: _io.BytesIO(), lambda: _io.StringIO(), lambda: sys.flags, lambda: sys.float_info,
        lambda: sys.long_info, lambda: sys.version_info, lambda: sys.getwindowsversion(),
        lambda: list.__dict__['append'], lambda: dict.__dict__['fromkeys'], lambda: _elementtree.TreeBuilder(),
        lambda: _elementtree.XMLParser(), lambda: _subprocess.GetCurrentProcess(),
    ]


def record_static(value):
    if isinstance(value, type) and not (value.__flags__ & HEAPTYPE):
        record(value)


walk(object)
for name in MODULES:
    try:
        module = __import__(name)
    except ImportError:
        continue
    walk(object)
    # Types a module init leaves unready are absent from
    # `object.__subclasses__()` until first use.
    for value in vars(module).values():
        record_static(value)
for factory in instance_factories():
    value = factory()
    record_static(type(value))
    record_static(value)
walk(object)

entries = []
for t in order:
    subclass = None
    if seen[t] & BASETYPE:
        try:
            subclass = type('X', (t,), {'__slots__': ()}).__flags__ & ~VALID_VERSION_TAG
        except (AttributeError, TypeError):
            subclass = None
    entries.append((key(t), seen[t] & 0xFFFFFFFF, subclass if subclass is None else subclass & 0xFFFFFFFF))

names = [entry[0] for entry in entries]
duplicates = sorted(set(name for name in names if names.count(name) > 1))
if duplicates:
    raise SystemExit('duplicate type names: %r' % duplicates)

lines = []
for name, flags, subclass in sorted(entries):
    lines.append('  {"name": "%s", "flags": %d, "subclass": %s}' % (name, flags, 'null' if subclass is None else subclass))
sys.stdout.write('[\n' + ',\n'.join(lines) + '\n]\n')
