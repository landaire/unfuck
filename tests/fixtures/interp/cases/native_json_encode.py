# The C encoder behind json.dumps and _json.encode_basestring_ascii.
import json
import _json


def K(value):
    return value


def err(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except Exception as error:
        return (type(error).__name__, str(error))


class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y


class Strish(str):
    pass


class Listish(list):
    def __iter__(self):
        return iter([u'from', u'iter'])


class Tuplish(tuple):
    pass


class Dictish(dict):
    pass


class Reordered(dict):
    def __iter__(self):
        return iter(sorted(dict.keys(self), reverse=True))

    def __getitem__(self, key):
        return ('item', dict.__getitem__(self, key))


class Intish(int):
    def __str__(self):
        return 'Intish!'


class Floatish(float):
    def __repr__(self):
        return 'Floatish!'


class PlainFloat(float):
    pass


def default(value):
    if isinstance(value, Point):
        return [value.x, value.y]
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(repr(value) + ' is not JSON serializable')


values = [
    None, True, False, 0, -7, 2 ** 40, -(2 ** 70), 1.0, 0.1, -2.5e-7, 1e16, 1e22, 123456789.125,
    'plain', u'unicode', u'caf\xe9 \u20ac', u'\U0001d11e', 'caf\xc3\xa9', '\x00\x1f\x7f',
    '"quoted" \\ / \b\f\n\r\t', u'\ud800', [], (), {}, [1, [2, [3, []]]], (1, (2,)), {1: 2}, {u'k': [None]},
    {2.5: 1}, {True: 1}, {None: 1}, {False: 0}, {7L: 1}, {u'\xe9': 1}, {'\xc3\xa9': 1},
    Strish('sub'), Listish([1, 2]), Tuplish((3, 4)), Dictish({1: 1}), Intish(5), Reordered({u'a': 1, u'b': 2, u'c': 3}),
    Floatish(1.5), PlainFloat(2.5), [Floatish(0.1)], {Floatish(3.5): 1}, {PlainFloat(4.5): 2},
    {u'alpha': 1, u'beta': 2, 'gamma': 3, u'delta': 4, 'epsilon': 5, u'zeta': 6},
    {'a': 1, 'b': 2, 'c': 3, 'ab': 4, 'ba': 5, 'abc': 6, 'cab': 7, u'\xe9': 8},
]

dumped = [json.dumps(value) for value in values]
unescaped = [json.dumps(value, ensure_ascii=False) for value in [u'caf\xe9', 'caf\xc3\xa9', [u'\u20ac', 'x'], u'\x00"\\']]
types = [type(json.dumps(value)).__name__ for value in [u'x', [u'x'], ['x'], [u'\xe9'], ['\xc3\xa9']]]

options = (
    json.dumps([1, {2: 3}], separators=(',', ':')),
    json.dumps([1, {2: 3}], separators=(' , ', ' : ')),
    json.dumps({u'b': 1, u'a': [1, 2]}, sort_keys=True),
    json.dumps([1, {2: [3]}], indent=2),
    json.dumps([Point(1, 2), set([3, 1])], default=default),
    json.dumps({1: Point(3, 4)}, default=default),
    json.dumps({(1, 2): 1, 3: 4}, skipkeys=True),
    json.dumps([float('inf'), float('-inf')]),
    json.dumps({float('inf'): 1}),
    json.dumps([1, 2], check_circular=False),
    json.dumps(['\xe9'], encoding='latin-1'),
    json.dumps(['\xe9'], encoding='latin-1', ensure_ascii=False),
)

loop = []
loop.append(loop)
cycle = {}
cycle[1] = [cycle]
shared = [1]

failures = (
    err(json.dumps, [Point(1, 2)])[0],
    err(json.dumps, {(1, 2): 1}),
    err(json.dumps, [float('nan')], allow_nan=False),
    err(json.dumps, {float('inf'): 1}, allow_nan=False),
    err(json.dumps, loop),
    err(json.dumps, cycle),
    err(json.dumps, [Point(0, 0)], default=lambda value: value),
    json.dumps([shared, shared, {1: shared}]),
    err(json.dumps, ['\xff']),
    err(json.dumps, [{1: 2}], default=None),
)

markers = {}
encoder = _json.make_encoder(markers, default, _json.encode_basestring_ascii, None, ': ', ', ', False, False, True)
python_encoder = _json.make_encoder(None, default, lambda text: '<' + text + '>', K(4), '=', ';', True, True, False)
deleted = {1: 1}
del deleted[1]
removed = {1: 1, 2: 2}
del removed[1]

chunks = (
    encoder([1, u'two', {3: None}, (4.5,)], 0),
    encoder({u'x': 1, u'y': 2, u'z': 3, u'xy': [Floatish(5.5)]}, 0),
    encoder(obj=[[]], _current_indent_level=7),
    encoder({}, 0),
    encoder(deleted, 0),
    encoder(removed, 0),
    encoder([Point(1, 2)], 0),
    markers,
    python_encoder([u'a', 'b', {1: 2, 2: [None]}, {(5,): 3}], 0),
    err(python_encoder, [float('nan')], 0),
    err(encoder, [1]),
    err(encoder, [1], 'x'),
    err(encoder, [1], 0, 0),
    err(_json.make_encoder, [], None, None, None, ':', ',', False, False, True),
    err(_json.make_encoder, None, None, None, None, ':', ',', False, False),
    _json.make_encoder(None, None, None, None, ':', ',', False, False, True)([None, True, False, 3], 0),
)

ascii_escapes = (
    _json.encode_basestring_ascii(K('plain text')),
    _json.encode_basestring_ascii(K('\x00\x08\x0c\n\r\t\x1f\x7f"\\/')),
    _json.encode_basestring_ascii(K('caf\xc3\xa9')),
    _json.encode_basestring_ascii(K(u'caf\xe9 \u20ac \U0001f600 \udc00')),
    _json.encode_basestring_ascii(K(u'')),
    _json.encode_basestring_ascii(Strish('x"y')),
    err(_json.encode_basestring_ascii, K('\xff')),
    err(_json.encode_basestring_ascii, 5),
    err(_json.encode_basestring_ascii),
    err(_json.encode_basestring_ascii, 'a', 'b'),
    err(_json.encode_basestring_ascii, text='a'),
)

shared_chunks = _json.make_encoder(None, None, None, None, ':', ',', False, False, True)([None, None, [], [], {}, {}], 0)
identity = [shared_chunks[index] is shared_chunks[index + 2] for index in (1, 5, 9)]

RESULT = (dumped, unescaped, types, options, failures, chunks, ascii_escapes, identity)
