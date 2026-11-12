# Runs one differential case of the CJK codecs: one-shot, incremental,
# and stream coding of the given text and bytes. CPython and the
# interpreter both run this module, so the returned text must depend only
# on codec behavior.
#
# A case is a dict: 'codec' names the codec, 'kind' the operations,
# 'text' holds UTF-16 units, 'data' byte values, 'errors' the error modes,
# and 'steps' the chunk sizes and operations of incremental and stream
# runs.

import codecs
import _multibytecodec
import _codecs_cn
import _codecs_hk
import _codecs_iso2022
import _codecs_jp
import _codecs_kr
import _codecs_tw

MODULES = {}
for module in (_codecs_cn, _codecs_hk, _codecs_iso2022, _codecs_jp, _codecs_kr, _codecs_tw):
    for name in ('gb2312', 'gbk', 'gb18030', 'hz', 'big5hkscs', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2', 'iso2022_jp_2004',
                 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr', 'shift_jis', 'cp932', 'euc_jp', 'shift_jis_2004', 'shift_jisx0213',
                 'euc_jis_2004', 'euc_jisx0213', 'euc_kr', 'cp949', 'johab', 'big5', 'cp950'):
        try:
            module.getcodec(name)
        except LookupError:
            continue
        MODULES[name] = module

log = []

# Handler calls after which a handler gives up with an out-of-range
# position, so that one that never advances still ends the case.
CALL_LIMIT = 200


def describe_error(error):
    return (type(error).__name__, error.encoding, error.start, error.end, error.reason, error.object)


def exhausted():
    return len(log) > CALL_LIMIT


def marking(error):
    log.append(describe_error(error))
    if exhausted():
        return (u'', 10 ** 6)
    if isinstance(error, UnicodeEncodeError):
        return (u'[%d]' % error.start, error.end)
    return (u'<%d>' % error.start, error.end)


def rewinding(error):
    # Resumes one unit after the start, counted from the end of the
    # object; zero would mean the start of the input.
    log.append(describe_error(error))
    position = error.start + 1 - len(error.object)
    if exhausted():
        return (u'', 10 ** 6)
    return (u'', position if position < 0 else error.end)


def unencodable(error):
    log.append(describe_error(error))
    if exhausted():
        return (u'', 10 ** 6)
    return (u'\u00e9\u4e00?', error.end)


def jumping(error):
    log.append(describe_error(error))
    return (u'#', len(error.object) + 1)


codecs.register_error('cjkdiff.mark', marking)
codecs.register_error('cjkdiff.rewind', rewinding)
codecs.register_error('cjkdiff.unencodable', unencodable)
codecs.register_error('cjkdiff.jump', jumping)


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return ('raised', type(error).__name__, str(error), getattr(error, 'args', None))


def text_of(units):
    return u''.join(map(unichr, units))


def bytes_of(values):
    return ''.join(map(chr, values))


def chunks(sequence, sizes):
    pieces = []
    position = 0
    for size in sizes:
        pieces.append(sequence[position:position + size])
        position += size
    pieces.append(sequence[position:])
    return pieces


class Chunked(object):
    """A stream that returns at most `size` bytes per read and records the
    calls it receives."""

    def __init__(self, data, size):
        self.data = data
        self.size = size
        self.calls = []

    def read(self, *args):
        self.calls.append(('read',) + args)
        size = args[0] if args else -1
        if size < 0 or size > self.size:
            size = self.size
        piece, self.data = self.data[:size], self.data[size:]
        return piece

    def readline(self, *args):
        self.calls.append(('readline',) + args)
        size = args[0] if args else -1
        end = self.data.find('\n') + 1 or len(self.data)
        if 0 <= size < end:
            end = size
        piece, self.data = self.data[:end], self.data[end:]
        return piece

    def write(self, data):
        self.calls.append(('write', data))


def oneshot(codec, text, data, errors):
    results = []
    for mode in errors:
        del log[:]
        results.append((mode, attempt(codec.encode, text, mode), attempt(codec.decode, data, mode), list(log)))
    return results


def incremental(name, text, data, errors, steps):
    module = MODULES[name]
    codec = module.getcodec(name)

    class Encoder(_multibytecodec.MultibyteIncrementalEncoder):
        pass

    class Decoder(_multibytecodec.MultibyteIncrementalDecoder):
        pass

    Encoder.codec = codec
    Decoder.codec = codec
    results = []
    for mode in errors:
        del log[:]
        encoder = Encoder(mode)
        pieces = [attempt(encoder.encode, piece) for piece in chunks(text, steps)]
        pieces.append(attempt(encoder.encode, u'', True))
        decoder = Decoder(mode)
        decoded = [attempt(decoder.decode, piece) for piece in chunks(data, steps)]
        decoded.append(attempt(decoder.decode, '', True))
        results.append((mode, pieces, decoded, list(log)))

    # Resets midway through.
    encoder = Encoder('replace')
    decoder = Decoder('replace')
    middle = len(steps) // 2
    first, second = chunks(text, steps[:middle] or [len(text) // 2])[:2]
    results.append([attempt(encoder.encode, first), encoder.reset(), attempt(encoder.encode, second, True)])
    first, second = chunks(data, steps[:middle] or [len(data) // 2])[:2]
    results.append([attempt(decoder.decode, first), decoder.reset(), attempt(decoder.decode, second, True)])
    return results


def streams(name, text, data, errors, steps):
    module = MODULES[name]
    codec = module.getcodec(name)

    class Reader(_multibytecodec.MultibyteStreamReader):
        pass

    class Writer(_multibytecodec.MultibyteStreamWriter):
        pass

    Reader.codec = codec
    Writer.codec = codec
    results = []
    for mode in errors:
        del log[:]
        stream = Chunked(data, 1 + steps[0] % 7 if steps else 3)
        reader = Reader(stream, mode)
        out = []
        for step in steps[1:] or [-1]:
            operation, size = step % 4, step // 4 - 2
            if operation == 0:
                out.append(attempt(reader.read, size))
            elif operation == 1:
                out.append(attempt(reader.readline, size))
            elif operation == 2:
                out.append(attempt(reader.readlines, size))
            else:
                out.append(attempt(reader.reset))
        out.append(attempt(reader.read))
        results.append((mode, out, stream.calls, list(log)))

        del log[:]
        stream = Chunked('', 0)
        writer = Writer(stream, mode)
        out = []
        for index, piece in enumerate(chunks(text, steps)):
            if index % 3 == 2:
                out.append(attempt(writer.writelines, [piece[:1], piece[1:]]))
            else:
                out.append(attempt(writer.write, piece))
            if index % 4 == 3:
                out.append(attempt(writer.reset))
        out.append(attempt(writer.reset))
        results.append((mode, out, stream.calls, list(log)))
    return results


def run_case(case):
    name = case['codec']
    text = text_of(case['text'])
    data = bytes_of(case['data'])
    errors = case['errors']
    steps = case['steps']
    kind = case['kind']
    if kind == 'oneshot':
        result = oneshot(MODULES[name].getcodec(name), text, data, errors)
    elif kind == 'incremental':
        result = incremental(name, text, data, errors, steps)
    else:
        result = streams(name, text, data, errors, steps)
    return repr(result)


def pool(name):
    """Characters the codec encodes alone, as UTF-16 units, with their
    encodings."""
    codec = MODULES[name].getcodec(name)
    chars = []
    codes = []
    for code_point in range(0x110000):
        if 0xd800 <= code_point < 0xe000:
            continue
        if code_point < 0x10000:
            text = unichr(code_point)
        else:
            offset = code_point - 0x10000
            text = unichr(0xd800 + (offset >> 10)) + unichr(0xdc00 + (offset & 0x3ff))
        try:
            encoded = codec.encode(text)[0]
        except UnicodeEncodeError:
            continue
        chars.append([ord(unit) for unit in text])
        codes.append([ord(byte) for byte in encoded])
    return {'chars': chars, 'codes': codes}
