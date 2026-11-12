# The C scanner behind json.loads, and _json.scanstring.
import json
import json.decoder
import _json


def K(value):
    return value


def items(value):
    if isinstance(value, dict):
        return sorted((key, items(item)) for key, item in value.items())
    if isinstance(value, list):
        return [items(item) for item in value]
    return value


documents = [
    K('{"a": [1, 2.5, -3, 1e3, -0.0, 0, 2147483647, true, false, null], "b": {"c": "d"}}'),
    K(u'{"a": [1, 2.5, -3, 1E-3, 1.5e+2, null], "\u00e9": "\\u00e9\\n\\t\\"\\\\\\/\\b\\f\\r"}'),
    K('  [ 1 , [ ] , { } , "x" ]  '),
    K('"caf\xc3\xa9"'),
    K(u'"\\ud834\\udd1e and \\ud800 alone"'),
    K('"\\uD834\\uDD1E"'),
    K('[NaN, Infinity, -Infinity]'),
    K('12345678901234567890'),
    K(u'-12345678901234567890'),
    K('[1e400, -1e400, 0.1, 123.456e-2]'),
    K('[2147483648, -2147483649, 4294967296, 9223372036854775807, -9223372036854775808]'),
]

decoded = [items(json.loads(document)) for document in documents]
types = [type(json.loads(K(text))).__name__ for text in ['"s"', u'"s"', '1', u'1', '1.5', u'1.5',
                                                         '2147483647', '2147483648', u'-2147483648', u'-2147483649']]
astral = [len(json.loads(K(text))) for text in [u'"\\ud83d\\ude00"', '"\xf0\x9f\x98\x80"', u'"\U0001F600"',
                                                  '"\\uD834\\uDD1E x"', u'"\U0001D11E\\ud800"']]

hooks = (
    json.loads(K('{"a": 1}'), object_hook=lambda d: ('hooked', items(d))),
    json.loads(K('{"b": 2, "a": 1}'), object_pairs_hook=lambda pairs: ('pairs', pairs)),
    json.loads(K(u'{"b": 2, "a": 1}'), object_pairs_hook=lambda pairs: ('pairs', pairs), object_hook=list),
    json.loads(K('[1.5, 2, 3e2]'), parse_float=lambda text: ('float', text), parse_int=lambda text: ('int', text)),
    json.loads(K(u'[1.5, 2]'), parse_float=lambda text: ('float', text), parse_int=lambda text: ('int', text)),
    json.loads(K('[NaN, -Infinity]'), parse_constant=lambda text: ('constant', text, type(text).__name__)),
    json.loads(K('"tab\there"'), strict=False),
    json.loads(K('"\xe9t\xe9"'), encoding='latin-1'),
    json.loads(K(u'{"k": [1, {"z": "\u20ac"}]}')),
)

decoder = json.decoder.JSONDecoder()
raw = (
    decoder.raw_decode(K('[1, 2] trailing')),
    decoder.raw_decode(K(u'{"x": 1}  ')),
    decoder.scan_once(K('xx"abc"yy'), 2),
    decoder.scan_once(K(u'[true]'), 0),
    decoder.scan_once(string=K('null'), idx=0),
    decoder.scan_once(K('1.5e'), 0),
    decoder.scan_once(K('1.e5'), 0),
    decoder.scan_once(K('-0.5E+3x'), 0),
    decoder.scan_once(K('012'), 0),
)

scanned = (
    _json.scanstring(K('"abc" tail'), 1),
    _json.scanstring(K(u'x"a\\u0041b"'), 2),
    _json.scanstring(K('"a\\nb"'), 1, None),
    _json.scanstring(K('"\xe9"'), 1, 'latin-1', 1),
    _json.scanstring(K('"a\tb"'), 1, 'utf-8', 0),
    _json.scanstring(K('"a\tb"'), 1, u'utf-8', False),
    _json.scanstring(K('"ab"'), 1L),
    _json.scanstring(K('"ab"'), True),
    _json.scanstring(K('"x\\ud834\\udd1ey"'), 1),
    repr(_json.scanstring(K(u'"\\ud83d\\ude00"'), 1)[0]),
    len(_json.scanstring(K(u'"\\ud83d\\ude00"'), 1)[0]),
    _json.scanstring(K(u'"\U0001F600"'), 1),
)

constants = json.loads(K('[NaN, NaN, -Infinity, -Infinity]'), parse_constant=lambda name: name)
identity = (constants[0] is constants[1], constants[2] is constants[3])

RESULT = (decoded, types, astral, hooks, raw, scanned, identity)
