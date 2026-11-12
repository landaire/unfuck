import _io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


def run(translate, chunks):
    d = _io.IncrementalNewlineDecoder(None, translate)
    out = []
    for chunk, final in chunks:
        out.append(d.decode(chunk, final))
        out.append(d.getstate())
    return out, d.newlines


chunks = [(u'a\r', False), (u'\nb\r', False), (u'c\n', False), (u'\r', False), (u'', True)]
plain = run(False, chunks)
translated = run(True, chunks)

newline_kinds = []
for text in (u'', u'a', u'\n', u'\r', u'\r\n', u'\r\n\n', u'\r\r', u'\r\n\r', u'\n\r\n\r'):
    d = _io.IncrementalNewlineDecoder(None, False)
    d.decode(text, final=True)
    newline_kinds.append(d.newlines)


class Inner(object):
    def __init__(self):
        self.calls = []

    def decode(self, data, final=False):
        self.calls.append(('decode', data, final))
        return data.decode('ascii')

    def getstate(self):
        return ('zz', 5)

    def setstate(self, state):
        self.calls.append(('setstate', state))

    def reset(self):
        self.calls.append(('reset',))


inner = Inner()
wrapped = _io.IncrementalNewlineDecoder(inner, True)
wrapped_out = (wrapped.decode('a\r\nb\r'), wrapped.getstate(), wrapped.setstate(('q', 7)), wrapped.reset(), wrapped.newlines, wrapped.decode('x', True))

d = _io.IncrementalNewlineDecoder(None, 0)
states = (failure(d.setstate, 1), failure(d.setstate, (1,)), failure(d.setstate, ('a', 1.5)), failure(d.setstate, ['a', 3]), d.getstate(), failure(d.setstate, ('a', -1)), d.getstate(), failure(d.setstate, ('a', 2 ** 70 + 1)), d.getstate(), d.reset(), d.getstate())

class Pair(object):
    def __len__(self):
        return 2

    def __getitem__(self, index):
        return ('b', 3)[index]


seq_state = (failure(d.setstate, Pair()), d.getstate(), failure(d.setstate, u'ab'), failure(d.setstate, 'ab'), failure(d.setstate, {}))

bare = _io.IncrementalNewlineDecoder.__new__(_io.IncrementalNewlineDecoder)

RESULT = (
    seq_state, plain, translated, newline_kinds, inner.calls, wrapped_out, states,
    failure(bare.decode, u'x'), failure(bare.getstate), failure(bare.reset), bare.newlines,
    failure(_io.IncrementalNewlineDecoder), failure(_io.IncrementalNewlineDecoder, None, 'x'),
    failure(_io.IncrementalNewlineDecoder, None, 1.5), failure(d.decode), failure(d.decode, u'x', 'y'),
    failure(d.decode, 'bytes'), failure(_io.IncrementalNewlineDecoder, None, 1, 'strict', 4),
)
