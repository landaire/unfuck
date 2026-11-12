# Decoder states of any two-item sequence, as TextIOWrapper reads them while
# reading and telling. A state that fails to parse crashes 2.7.12, so only
# valid states appear.

import _codecs
import _io


class Pair(object):
    def __init__(self, items):
        self.items = items

    def __len__(self):
        return len(self.items)

    def __getitem__(self, index):
        return self.items[index]


STATES = {
    'tuple': lambda: ('', 0),
    'list': lambda: ['', 0],
    'pair': lambda: Pair(['', 0]),
    'pending': lambda: Pair(['x', 0]),
}


class Decoder(object):
    kind = None

    def __init__(self, errors='strict'):
        pass

    def decode(self, data, final=False):
        return data.decode('ascii')

    def getstate(self):
        return STATES[Decoder.kind]()

    def setstate(self, state):
        pass

    def reset(self):
        pass


class Encoder(object):
    def __init__(self, errors='strict'):
        pass

    def encode(self, text, final=False):
        return text.encode('ascii')

    def setstate(self, state):
        pass

    def reset(self):
        pass


class Info(tuple):
    incrementalencoder = Encoder
    incrementaldecoder = Decoder
    name = 'statecase'


def search(name):
    if name == 'statecase':
        return Info((None, None, None, None))
    return None


_codecs.register(search)


def attempt(function):
    try:
        return ('ok', function())
    except Exception as e:
        return (type(e).__name__, str(e))


RESULT = []
for kind in sorted(STATES):
    Decoder.kind = kind
    text = _io.TextIOWrapper(_io.BytesIO('abcdef'), 'statecase', 'strict', '\n')
    text._CHUNK_SIZE = 2
    RESULT.append((kind, attempt(lambda: text.read(1)), attempt(text.tell), attempt(lambda: text.read(2)), attempt(text.tell)))
