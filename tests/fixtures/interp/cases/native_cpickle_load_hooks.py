import cPickle
import codecs
import encodings.cp1252
import re
import imp
import sys
import cStringIO
import copy_reg


# Pickles name globals of this module; the reference runs cases outside
# sys.modules, so they are published under a registered module.
HOST = imp.new_module('cpickle_load_host')
sys.modules['cpickle_load_host'] = HOST


def K(x):
    return x


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


class Reader(object):
    """A file-like object that records how cPickle reads it."""

    def __init__(self, data):
        self.data = data
        self.position = 0
        self.log = []

    def read(self, count):
        self.log.append(('read', count))
        chunk = self.data[self.position:self.position + count]
        self.position += len(chunk)
        return chunk

    def readline(self):
        self.log.append('readline')
        end = self.data.find('\n', self.position)
        end = len(self.data) if end < 0 else end + 1
        line = self.data[self.position:end]
        self.position = end
        return line


HOST.Reader = Reader
RESULT = []

# Reads through a Python file-like object.
reader = Reader(K("(lp0\nI1\naS'two'\np1\naF3.5\na(dp2\ng1\nI4\nsa.K\x05."))
RESULT.append((cPickle.load(reader), reader.log))
reader.log = []
RESULT.append((cPickle.load(reader), reader.log))
reader.log = []
RESULT.append((failure(cPickle.load, reader), reader.log))

binary = Reader(K('\x80\x02]q\x00(K\x01U\x03abcq\x01X\x02\x00\x00\x00\xc3\xa9h\x01e.'))
RESULT.append((cPickle.load(binary), binary.log))


class UnicodeReader(Reader):
    def read(self, count):
        return unicode(Reader.read(self, count))

    def readline(self):
        return unicode(Reader.readline(self))


RESULT.append(cPickle.load(UnicodeReader(K('I12\n.'))))


class BadRead(Reader):
    def read(self, count):
        return 5


class ShortRead(Reader):
    def read(self, count):
        return 'x' * (count + 1)


class RaisingRead(Reader):
    def read(self, count):
        raise EOFError('custom')


class OnlyRead(object):
    def read(self, count):
        return ''


RESULT.append(failure(cPickle.load, BadRead('N.')))
RESULT.append(failure(cPickle.load, ShortRead('N.')))
RESULT.append(failure(cPickle.load, RaisingRead('N.')))
RESULT.append(failure(cPickle.load, OnlyRead()))
RESULT.append(failure(cPickle.Unpickler, OnlyRead()))

# cStringIO input, read in sequence.
stream = cStringIO.StringIO(K("I1\n.S'x'\n.K\x02."))
RESULT.append((cPickle.load(stream), stream.tell()))
RESULT.append((cPickle.load(stream), stream.tell()))
RESULT.append((cPickle.load(stream), stream.tell()))
RESULT.append((failure(cPickle.load, stream), stream.tell()))
partial = cStringIO.StringIO(K('T\x05\x00\x00\x00ab'))
RESULT.append((failure(cPickle.load, partial), partial.tell()))
closed = cStringIO.StringIO(K('N.'))
closed.close()
RESULT.append(failure(cPickle.load, closed))
output = cStringIO.StringIO()
output.write(K('I7\n.'))
output.seek(0)
RESULT.append(cPickle.load(output))

# Unpickler attributes.
unpickler = cPickle.Unpickler(cStringIO.StringIO(K('(lp0\nI1\nag0\n.')))
RESULT.append(type(unpickler).__name__)
RESULT.append(type(unpickler).__module__)
RESULT.append(unpickler.__methods__)
for name in ['persistent_load', 'find_global', 'foo', '__class__', '__dict__']:
    RESULT.append(failure(getattr, unpickler, name))
RESULT.append(unpickler.memo)
RESULT.append(unpickler.UnpicklingError is cPickle.UnpicklingError)
RESULT.append(type(unpickler.load).__name__)
RESULT.append(unpickler.load.__name__)
RESULT.append(unpickler.load.__self__ is unpickler)
RESULT.append(unpickler.load())
RESULT.append(sorted(unpickler.memo.items()))
RESULT.append(failure(unpickler.load))
RESULT.append(failure(unpickler.load, 1))
RESULT.append(failure(setattr, unpickler, 'memo', []))
RESULT.append(failure(setattr, unpickler, 'foo', 1))
RESULT.append(failure(delattr, unpickler, 'memo'))
RESULT.append(failure(delattr, unpickler, 'foo'))
unpickler.persistent_load = len
RESULT.append(unpickler.persistent_load is len)
del unpickler.persistent_load
RESULT.append(failure(getattr, unpickler, 'persistent_load'))
unpickler.find_global = None
RESULT.append(unpickler.find_global)
del unpickler.find_global
RESULT.append(failure(type(unpickler)))
RESULT.append(sorted(type(unpickler).__dict__.keys()))
RESULT.append(dir(unpickler))
RESULT.append((repr(type(unpickler)), repr(unpickler).startswith('<cPickle.Unpickler object at ')))
RESULT.append(failure(object.__getattribute__, unpickler, 'memo'))


class DerivedUnpickler(type(unpickler)):
    pass


RESULT.append(failure(DerivedUnpickler))

# NEWOBJ of types without tp_new.
for unconstructible in (type(unpickler), DerivedUnpickler, type(cStringIO.StringIO()), type(cStringIO.StringIO('x'))):
    newobj = cPickle.Unpickler(cStringIO.StringIO(K('\x80\x02cmodule\nname\n)\x81.')))
    newobj.find_global = lambda module, name: unconstructible
    RESULT.append(failure(newobj.load))

# The charmap encoding map and the compiled pattern have no tp_new either.
for unconstructible in (type(codecs.charmap_build(encodings.cp1252.decoding_table)), type(re.compile(K('a')))):
    newobj = cPickle.Unpickler(cStringIO.StringIO(K('\x80\x02cmodule\nname\n)\x81.')))
    newobj.find_global = lambda module, name: unconstructible
    RESULT.append(failure(newobj.load))
    RESULT.append(failure(unconstructible))

# A memo shared with a later load.
memo_reader = cPickle.Unpickler(cStringIO.StringIO(K("S'shared'\np5\n.g5\n.")))
first = memo_reader.load()
RESULT.append((first, memo_reader.load() is first))
memo_reader = cPickle.Unpickler(cStringIO.StringIO(K('g9\n.')))
memo_reader.memo = {'9': 'preset'}
RESULT.append(memo_reader.load())

# persistent_load as a function and as a list.
persistent = cPickle.Unpickler(cStringIO.StringIO(K("(lp0\nPone\naS'two'\nQa.")))
persistent.persistent_load = lambda pid: ('loaded', pid)
RESULT.append(persistent.load())
collected = []
persistent = cPickle.Unpickler(cStringIO.StringIO(K("(lp0\nPone\naS'two'\nQa.")))
persistent.persistent_load = collected
RESULT.append((persistent.load(), collected))
persistent = cPickle.Unpickler(cStringIO.StringIO(K('Pid\n.')))
persistent.persistent_load = None
RESULT.append(failure(persistent.load))

# find_global.
calls = []


def find_global(module, name):
    calls.append((module, name))
    if name == 'Other':
        return lambda *args: ('built', module, name, args)
    return (module, name)


finder = cPickle.Unpickler(cStringIO.StringIO(K('(cmod\nname\n(icpickle_load_host\nOther\nt.')))
finder.find_global = find_global
RESULT.append((finder.load(), calls))
finder = cPickle.Unpickler(cStringIO.StringIO(K('c__builtin__\nlen\n.')))
finder.find_global = None
RESULT.append(failure(finder.load))

# noload walks the opcodes without building objects.
walker = cPickle.Unpickler(cStringIO.StringIO(K(
    "(lp0\nI1\naccopy_reg\n_reconstructor\n(ccpickle_load_host\nNope\nc__builtin__\nobject\nNtRp1\n(dp2\nS'a'\nPpid\nsbaPother\na.")))
found = []
walker.persistent_load = found
RESULT.append((walker.noload(), found))
walker = cPickle.Unpickler(cStringIO.StringIO(K('\x80\x02]q\x00(K\x01\x82\x05ccpickle_load_host\nNope\n)\x81}b(icpickle_load_host\nNope\nN}\x86be.')))
RESULT.append(walker.noload())
walker = cPickle.Unpickler(cStringIO.StringIO(K('(K\x01K\x02o.')))
RESULT.append(walker.noload())
walker = cPickle.Unpickler(cStringIO.StringIO(K('\x00')))
RESULT.append(failure(walker.noload))
walker = cPickle.Unpickler(cStringIO.StringIO(K('')))
RESULT.append(failure(walker.noload))

# The extension registry. The reference runs every case in one process, so
# this section undoes its registrations at the end.
copy_reg.clear_extension_cache()
copy_reg.add_extension('cpickle_load_host', 'Reader', 0xf0)
copy_reg.add_extension('__builtin__', 'len', 0x1234)
copy_reg.add_extension('__builtin__', 'abs', 0x12345678)
RESULT.append(cPickle.loads(K('\x80\x02\x82\xf0.')) is Reader)
RESULT.append(cPickle.loads(K('\x80\x02\x83\x34\x12.')) is len)
RESULT.append(cPickle.loads(K('\x80\x02\x84\x78\x56\x34\x12.')) is abs)
RESULT.append([code in copy_reg._extension_cache for code in (0xf0, 0x1234, 0x12345678, 0x79)])
copy_reg._inverted_registry[0x77] = ('only one',)
RESULT.append(failure(cPickle.loads, '\x80\x02\x82\x77.'))
copy_reg._inverted_registry[0x78] = ('__builtin__', 5)
RESULT.append(failure(cPickle.loads, '\x80\x02\x82\x78.'))
copy_reg._inverted_registry[0x79] = ('__builtin__', 'no_such_name')
RESULT.append(failure(cPickle.loads, '\x80\x02\x82\x79.'))
extension_finder = cPickle.Unpickler(cStringIO.StringIO(K('\x80\x02\x82\x79.')))
extension_finder.find_global = lambda module, name: 'found ' + name
RESULT.append(extension_finder.load())
RESULT.append(copy_reg._extension_cache[0x79])
copy_reg.remove_extension('cpickle_load_host', 'Reader', 0xf0)
RESULT.append(failure(cPickle.loads, '\x80\x02\x82\xf0.'))
copy_reg.remove_extension('__builtin__', 'len', 0x1234)
copy_reg.remove_extension('__builtin__', 'abs', 0x12345678)
for code in (0x77, 0x78, 0x79):
    del copy_reg._inverted_registry[code]
copy_reg.clear_extension_cache()

# Round trips of the pickler's output.
VALUES = [
    None, True, False, 0, 1, -1, 255, 256, 65535, 65536, -65536, 2 ** 31 - 1, -2 ** 31, 2 ** 62, 3L, -2 ** 100,
    0.0, -2.5, 1e300, 'abc', '', 'a\nb\\c\'"', '\x00\xff' * 3, u'', u'abc', u'\xe9\u20ac\n\\',
    (), (1,), (1, 2), (1, 2, 3), (1, 2, 3, 4), [], [1, [2]], {}, {'a': 1, 2: (3,)},
    range(1200), dict.fromkeys(range(1100)), len, copy_reg._reconstructor,
]
for protocol in (0, 1, 2):
    for value in VALUES:
        data = cPickle.dumps(K(value), protocol)
        loaded = cPickle.loads(data)
        if loaded != value or type(loaded) is not type(value):
            RESULT.append(('round trip differs', protocol, value, loaded))
shared = [1, 2]
nested = [shared, (shared, shared), {'k': shared}]
for protocol in (0, 1, 2):
    loaded = cPickle.loads(cPickle.dumps(nested, protocol))
    RESULT.append((loaded, loaded[0] is loaded[1][0] is loaded[2]['k']))
recursive = []
recursive.append(recursive)
for protocol in (0, 1, 2):
    loaded = cPickle.loads(cPickle.dumps(recursive, protocol))
    RESULT.append(loaded[0] is loaded)
