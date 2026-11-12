# State handling of the multibyte codecs: ISO-2022 escapes that designate
# nothing, the state incremental and stream objects keep when a call
# raises, sequences cut short at the end of the last call, and other
# byte-level details.
import codecs


def K(value):
    return value


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, str(error))


seen = []


def marking(error):
    seen.append((type(error).__name__, error.start, error.end, error.reason, error.object))
    return (u'<%d>' % error.start, error.end)


def plus_one(error):
    seen.append((type(error).__name__, error.start, error.end, error.reason, error.object))
    return (u'', error.start + 1)


def far(error):
    return (u'#', len(error.object) + 1)


codecs.register_error('states.mark', marking)
codecs.register_error('states.plus1', plus_one)
codecs.register_error('states.far', far)


def decode(name, data, errors='states.mark'):
    del seen[:]
    return (attempt(K(data).decode, name, errors), list(seen))


def encode(name, text, errors='strict'):
    return attempt(K(text).encode, name, errors)


def calls(target, method, arguments):
    results = []
    for item in arguments:
        results.append(attempt(getattr(target, method), *item))
    return results


class Chunked(object):
    def __init__(self, data, size):
        self.data = data
        self.size = size
        self.calls = []

    def read(self, *args):
        self.calls.append(args)
        size = args[0] if args else -1
        if size < 0 or size > self.size:
            size = self.size
        piece, self.data = self.data[:size], self.data[size:]
        return piece

    readline = read


E = '\x1b'
results = []

# An ESC that starts no designation passes bytes through up to one in @-Z.
for data in [E + E + '$' + E + '$BP-', E + 'Z' + E + '$BP-', E + '\x80' + E + '(J\\', E + '$BP-' + E + E + 'abP-', E + '[ab', 'a' + E + 'Q' + E + '$BP-']:
    results.append((data, decode('iso2022_jp', data), decode('iso2022_kr', data)))

# Six bytes ending in ESC $ B designate JIS X 0208, and &@ does not end an
# escape sequence.
for data in [E + '$\xd8' + E + '$BBy', E + '(a' + E + '$BBy', E + '&@' + E + '$BBy', E + '$' + E + '&@' + E + '$BBy', E + '$' + E + '$BBy', E + '&A' + E + '$BBy']:
    results.append((data, decode('iso2022_jp', data), decode('iso2022_jp_2004', data), decode('iso2022_kr', data)))

# Escapes of unknown sets, cut short, or too long.
for data in [E + '(J', E + '$(Q', E + '(' + '0' * 10, E + '(' + '0' * 14 + 'B', E + '.A' + E + 'Na', E + 'N']:
    results.append((data, decode('iso2022_jp', data), decode('iso2022_jp_2', data)))

decoder = codecs.getincrementaldecoder('iso2022_jp')('states.mark')
results.append(calls(decoder, 'decode', [(E + '$B' + E + '[',), ('ab',), ('PP-',), ('', True)]))
decoder = codecs.getincrementaldecoder('iso2022_jp')()
results.append(calls(decoder, 'decode', [(E + '$(',), (E + '$BZA',), (E + '\x80',), ()]))
results.append([decoder.reset(), decoder.decode('$BP-')])

# A sequence cut short at the end of the last call: the handler's
# replacement ends the call and the rest stays for the next one.
del seen[:]
decoder = codecs.getincrementaldecoder('euc_kr')('states.plus1')
results.append((calls(decoder, 'decode', [('\xa4\xd4\xa4\xb5x',), ('', True), ('', True)]), list(seen)))
for size in [-1, 9]:
    del seen[:]
    stream = Chunked('\xa4\xd4\xa4\xb5x', 9)
    reader = codecs.getreader('euc_kr')(stream, 'states.plus1')
    results.append((reader.read(size), reader.read(size), stream.calls, list(seen)))
del seen[:]
results.append((decode('euc_kr', 'a\xa4\xd4\xa4\xb5xy', 'states.plus1'), list(seen)))

# A call that raises: decoders drop what they held back, encoders keep
# it, and both keep the state they reached.
decoder = codecs.getincrementaldecoder('gbk')()
results.append(calls(decoder, 'decode', [('a\xd6',), ('\xffb\xd6',), ('\xd0c',), ('', True)]))
decoder = codecs.getincrementaldecoder('iso2022_jp')()
results.append(calls(decoder, 'decode', [(E + '$BF|\xff',), ('F|',), ('', True)]))
encoder = codecs.getincrementalencoder('big5hkscs')()
results.append(calls(encoder, 'encode', [(u'a\xca',), (u'\u0100',), (u'b',), (u'', True)]))
encoder = codecs.getincrementalencoder('iso2022_jp')()
results.append(calls(encoder, 'encode', [(u'\u65e5\u0100',), (u'\u65e5',), (u'', True)]))
encoder = codecs.getincrementalencoder('iso2022_jp')('states.far')
results.append(calls(encoder, 'encode', [(u'\u65e5\u0100',), (u'', True)]))


class Sink(object):
    def __init__(self):
        self.written = []

    def write(self, data):
        self.written.append(data)


sink = Sink()
writer = codecs.getwriter('big5hkscs')(sink)
results.append((calls(writer, 'write', [(u'\xca',)]), calls(writer, 'reset', [(), ()]), sink.written))
sink = Sink()
writer = codecs.getwriter('hz')(sink, 'states.far')
results.append((calls(writer, 'write', [(u'\u4e2d\u0100',), (u'\u4e2d',)]), calls(writer, 'reset', [()]), sink.written))

# The JIS X 0213 encoders drop a NUL after a character that can start a
# combining pair.
for name in ['euc_jis_2004', 'shift_jisx0213', 'big5hkscs', 'iso2022_jp_2004', 'iso2022_jp_3']:
    results.append((name, encode(name, u'\u304b\x00a'), encode(name, u'\xca\x00a'), encode(name, u'\u65e5\x00a')))
encoder = codecs.getincrementalencoder('euc_jis_2004')()
results.append(calls(encoder, 'encode', [(u'\u304b',), (u'\x00',), (u'a',), (u'', True)]))

# Four-byte gb18030 codes at the ends of their ranges. A third byte of FF
# carries into the next index.
for data in ['\x841\xa49', '\x841\xa50', '\x8f9\xfe9', '\x8f9\xff0', '\x900\x810', '\xe32\x9a5', '\xe32\x9a6', '\x81\x30',
             '\x810\xff0', '\x841\xff0', '\xe32\xff0']:
    results.append((data, decode('gb18030', data)))

# Composed Hangul in EUC-KR and the Johab layout.
for data in ['\xa4\xd4\xa4\xa1\xa4\xbf\xa4\xd4', '\xa4\xd4\xa4\xa1\xa4\xbf\xa4\xa2', '\xa4\xd4\xa4\xa1\xa4\xbf\xa4\xbf', '\xa4\xd4ab']:
    results.append((data, decode('euc_kr', data)))
results.append([encode('euc_kr', K(u'\uac02\u3164')), encode('johab', K(u'\u3131\u3164\u3000\uac00\u314f'))])
for data in ['\x88a', '\x88A', '\x84a', '\xd91', '\xda\xd4', '\x84\x41', '\xd9\xa1']:
    results.append((data, decode('johab', data)))

# Shift_JIS bytes that start nothing report two bytes even at the end.
for name in ['shift_jis', 'cp932', 'shift_jis_2004']:
    results.append((name, decode(name, '\x80'), decode(name, 'a\xa0b'), decode(name, '\xfd')))

# Handler positions: negative ones count from the end, and an integer too
# large for 64 bits reports as -1 without being resolved.
gb2312 = codecs.lookup('gb2312')
for index, position in enumerate([10 ** 100, -10 ** 100, 2 ** 64, 2 ** 31, 5, -5, 1L, True]):
    name = 'states.position%d' % index
    codecs.register_error(name, lambda error, position=position: (u'X', position))
    results.append((attempt(gb2312.encode, K(u'\u20ac'), name), attempt(gb2312.decode, K('\xff'), name)))

RESULT = results
