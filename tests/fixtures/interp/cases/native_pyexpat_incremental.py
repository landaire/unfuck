import StringIO
import pyexpat


def K(value):
    return value


def failure(function, *args):
    try:
        return ('ok', function(*args))
    except Exception as e:
        return (type(e).__name__, str(e))


DOC = K('<?xml version="1.0"?>\n<root a="1">text &amp; more <![CDATA[cdata]]> tail\xc3\xa9<child>inner</child>\n\n<!-- c --> end</root>\n')


def split(size):
    return [DOC[start:start + size] for start in range(0, len(DOC), size)]


def chunked(chunks, buffer_text, buffer_size=None):
    p = pyexpat.ParserCreate()
    if buffer_size is not None:
        p.buffer_size = buffer_size
    p.buffer_text = buffer_text
    log = []
    p.CharacterDataHandler = lambda data: log.append(('chars', data, p.buffer_used))
    p.StartElementHandler = lambda name, attributes: log.append(('start', name))
    p.EndElementHandler = lambda name: log.append(('end', name))
    p.CommentHandler = lambda data: log.append(('comment', data))
    results = []
    for chunk in chunks:
        results.append(p.Parse(chunk))
        results.append(p.buffer_used)
    results.append(p.Parse(K(''), K(1)))
    return (log, results, p.buffer_text, p.buffer_size)


# Chunks split tokens and multi-byte characters.
tags = DOC.replace(K('>'), K('>\x00')).split(K('\x00'))
chunkings = (tags, split(1), split(3), split(5), split(7), split(13), split(1000))
unbuffered = [chunked(chunks, False) for chunks in chunkings]
buffered = [chunked(chunks, True) for chunks in chunkings]
small_buffer = (chunked(tags, True, 6), chunked(split(20), True, 4))

# buffer_size validation; setting it turns buffering on.
p = pyexpat.ParserCreate()
size_checks = (
    failure(setattr, p, 'buffer_size', K('8')),
    failure(setattr, p, 'buffer_size', K(0)),
    failure(setattr, p, 'buffer_size', K(-5)),
    failure(setattr, p, 'buffer_size', K(1.5)),
    p.buffer_text,
    failure(setattr, p, 'buffer_size', K(8192)),
    p.buffer_text,
    failure(setattr, p, 'buffer_size', K(16)),
    p.buffer_text,
    p.buffer_size,
    failure(setattr, p, 'buffer_size', K(True)),
    p.buffer_size,
)

# Turning buffering off flushes buffered text to the handler.
p = pyexpat.ParserCreate()
p.buffer_text = K(1)
flushed = []
p.CharacterDataHandler = flushed.append
p.Parse(K('<r>abc'))
flushed.append(('used', p.buffer_used))
p.buffer_text = K(0)
flushed.append(('used', p.buffer_used, p.buffer_text))
p.Parse(K('def</r>'), K(1))

# Replacing the character data handler flushes with the old one.
p = pyexpat.ParserCreate()
p.buffer_text = K(1)
first, second = [], []
p.CharacterDataHandler = first.append
p.Parse(K('<r>abc'))
p.CharacterDataHandler = second.append
p.Parse(K('def</r>'), K(1))
replaced = (first, second)

# Changing buffer_size flushes too.
p = pyexpat.ParserCreate()
p.buffer_text = K(1)
resized = []
p.CharacterDataHandler = resized.append
p.Parse(K('<r>abc'))
p.buffer_size = K(3)
p.Parse(K('defghij</r>'), K(1))

# ParseFile reads 2048-byte chunks until read() returns ''.


class Reader(object):
    def __init__(self, data):
        self.data = data
        self.sizes = []

    def read(self, size):
        self.sizes.append(size)
        chunk, self.data = self.data[:size], self.data[size:]
        return chunk


big = K('<r>') + K('<i>x</i>') * 600 + K('</r>')
reader = Reader(big)
p = pyexpat.ParserCreate()
count = [0]


def count_start(name, attributes):
    count[0] += 1


p.StartElementHandler = count_start
parse_file = (p.ParseFile(reader), reader.sizes, count[0])

p = pyexpat.ParserCreate()
seen = []
p.StartElementHandler = lambda name, attributes: seen.append(name)
string_io = (p.ParseFile(StringIO.StringIO(K('<a><b/></a>'))), seen)


class BadReader(object):
    def __init__(self, result):
        self.result = result

    def read(self, size):
        return self.result


file_errors = []
for result in (K(u'<a/>'), K(5), K('x' * 2049)):
    p = pyexpat.ParserCreate()
    file_errors.append(failure(p.ParseFile, BadReader(result)))
p = pyexpat.ParserCreate()
file_errors.append(failure(p.ParseFile, K(42)))
p = pyexpat.ParserCreate()
file_errors.append(failure(p.ParseFile, StringIO.StringIO(K('<a>'))))

# read() may parse with the same parser; the outer ParseFile then finds
# the parse finished.


class ParsingReader(object):
    def __init__(self, parser):
        self.parser = parser
        self.inner = []

    def read(self, size):
        self.inner.append(self.parser.Parse(K('<a/>'), K(1)))
        return K('<b/>')


p = pyexpat.ParserCreate()
reentrant_reader = ParsingReader(p)
reentrant = (failure(p.ParseFile, reentrant_reader), reentrant_reader.inner, p.ErrorCode)

# Parsing after the final chunk fails.
p = pyexpat.ParserCreate()
p.Parse(K('<a/>'), K(1))
after_final = (failure(p.Parse, K('<b/>')), p.ErrorCode, failure(p.ParseFile, StringIO.StringIO(K('x'))))

RESULT = (
    unbuffered,
    buffered,
    small_buffer,
    size_checks,
    flushed,
    replaced,
    resized,
    parse_file,
    string_io,
    file_errors,
    reentrant,
    after_final,
)
