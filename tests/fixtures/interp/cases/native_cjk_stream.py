# Stream readers and writers of the multibyte codecs over StringIO.
import codecs
import cStringIO


def K(value):
    return value


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, str(error))


class Chunked(object):
    """A stream that returns at most `size` bytes per read."""

    def __init__(self, data, size):
        self.data = data
        self.size = size
        self.calls = []

    def read(self, size=-1):
        self.calls.append(size)
        if size < 0 or size > self.size:
            size = self.size
        piece, self.data = self.data[:size], self.data[size:]
        return piece

    readline = read


results = []

data = K(u'\u65e5\u672c\u8a9e\nabc\n\u30c6\u30b9\u30c8').encode('shift_jis')
reader = codecs.getreader('shift_jis')(cStringIO.StringIO(data))
results.append([reader.read(1), reader.read(3), reader.read()])

reader = codecs.getreader('shift_jis')(cStringIO.StringIO(data))
results.append(reader.readlines())

reader = codecs.getreader('shift_jis')(cStringIO.StringIO(data))
results.append([reader.readline(), reader.readline(), reader.readline(), reader.readline()])

stream = Chunked(K(u'\u4e2d\u6587abc').encode('gbk'), 1)
reader = codecs.getreader('gbk')(stream)
results.append([reader.read(1), reader.read(1), reader.read(5), reader.read(5), stream.calls])

reader = codecs.getreader('gbk')(cStringIO.StringIO(K('ab\xd6')))
results.append(attempt(reader.read))
reader = codecs.getreader('gbk')(cStringIO.StringIO(K('ab\xd6')), 'replace')
results.append(reader.read())
reader = codecs.getreader('gbk')(cStringIO.StringIO(K('ab\xd6')))
results.append([reader.read(2), attempt(reader.read, 1)])

reader = codecs.getreader('iso2022_jp')(cStringIO.StringIO(K('\x1b$BF|K\\\x1b(Babc')))
results.append([reader.read(4), reader.reset(), reader.read()])
results.append(attempt(reader.read, K('3')))
results.append(attempt(reader.read, 1, 2))

class NotString(object):
    def read(self, *args):
        return 5

results.append(attempt(codecs.getreader('gbk')(NotString()).read))

output = cStringIO.StringIO()
writer = codecs.getwriter('iso2022_jp')(output)
writer.write(K(u'a\u65e5'))
writer.writelines([K(u'\u672c'), K(u'b'), K('c')])
results.append(output.getvalue())
writer.write(K(u'\u8a9e'))
writer.reset()
results.append(output.getvalue())
results.append(attempt(writer.writelines, 5))
results.append(attempt(writer.write, K(u'\u00e9')))
results.append(writer.stream is output)
results.append(attempt(setattr, writer, 'stream', None))

output = cStringIO.StringIO()
writer = codecs.getwriter('big5hkscs')(output, 'replace')
writer.write(K(u'\u00ca'))
results.append(output.getvalue())
writer.write(K(u'\u0304\u00e9'))
results.append(output.getvalue())
writer.write(K(u'\u00ea'))
writer.reset()
results.append((output.getvalue(), writer.errors))

output = cStringIO.StringIO()
writer = codecs.getwriter('hz')(output)
writer.write(K(u'\u4e2d'))
writer.reset()
writer.reset()
results.append(output.getvalue())

recoded = cStringIO.StringIO(K(u'\ud55c\uad6d').encode('euc_kr'))
pair = codecs.StreamReaderWriter(recoded, codecs.getreader('euc_kr'), codecs.getwriter('euc_kr'))
results.append(pair.read())

RESULT = results
