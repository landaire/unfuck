# Errors of the C scanner: messages and positions through
# json.decoder.errmsg, which differ between str and unicode documents.
import json
import json.decoder
import _json


def K(value):
    return value


def err(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except Exception as error:
        return (type(error).__name__, str(error))


bad = [
    '', ' ', '[', '[1', '[1,', '[1 2]', '{', '{"a"', '{"a" 1}', '{"a": 1 "b": 2}', '{1: 2}', '{"a": }',
    '"abc', '"a\\', '"\\x"', '"\\u12"', '"\\u12zz"', '"\\u123"', '"a\nb"', '"a\x01"',
    'nul', 'tru', 'fals', 'NaNx', '-', '-x', '[-]', 'Infinit', '1 2', '{"a": 1,}', '[1,]',
    '"', '\n\n  [1,\n  x]', '{"a":1}x', '\xff', '"\xff"',
]

str_errors = [err(json.loads, K(text)) for text in bad]
unicode_errors = [err(json.loads, K(text.decode('latin-1'))) for text in bad]

decoder = json.decoder.JSONDecoder()
scanner_errors = (
    err(decoder.scan_once, K('abc'), 0),
    err(decoder.scan_once, K('[]'), 5),
    err(decoder.scan_once, K('[]'), -1),
    err(decoder.scan_once, K(u'[]'), -2),
    err(decoder.scan_once, 5, 0),
    err(decoder.scan_once, K('[]'), 'x'),
    err(decoder.scan_once, K('[]'), 1.5),
    err(decoder.scan_once, K('[]')),
    err(decoder.scan_once, K('[]'), 0, 1),
    err(decoder.scan_once, K('[]'), idx=0, extra=1),
    err(decoder.scan_once, K('[]'), 0, idx=0),
    err(decoder.scan_once, K('[]'), 2 ** 70),
)

scanstring_errors = (
    err(_json.scanstring, K('"abc"'), 0 - 1),
    err(_json.scanstring, K('"abc"'), -2 ** 63),
    err(_json.scanstring, K(u'"abc"'), -2 ** 63),
    err(_json.scanstring, K('"abc"'), 5),
    err(_json.scanstring, K('"abc"'), 6),
    err(_json.scanstring, K(''), 0),
    err(_json.scanstring, 1, 1),
    err(_json.scanstring, K('"abc"')),
    err(_json.scanstring, K('"abc"'), 1, None, 1, 2),
    err(_json.scanstring, K('"abc"'), 1, 5),
    err(_json.scanstring, K('"abc"'), 1, 'a\x00b'),
    err(_json.scanstring, K('"abc"'), 1, None, 1.5),
    err(_json.scanstring, K('"abc"'), end=1),
    err(_json.scanstring, K('"abc"'), 'x'),
    err(_json.scanstring, K('"abc"'), 1, 'no-such-codec'),
    err(_json.scanstring, K('"\xff"'), 1),
    err(_json.scanstring, K('"\xff"'), 1, 'ascii'),
    err(_json.scanstring, K('"\x1f"'), 1, None, 1),
    err(_json.scanstring, K(u'"\\uXYZW"'), 1),
)

class Context(object):
    encoding = None
    strict = True
    object_hook = None
    object_pairs_hook = None
    parse_float = float
    parse_int = int
    parse_constant = None


class BadEncoding(Context):
    encoding = 5


class Missing(object):
    encoding = 'utf-8'


hooks_raise = (
    err(json.loads, K('[1]'), parse_int=lambda text: 1 / 0),
    err(json.loads, K('{}'), object_hook=lambda value: {}['missing']),
    err(_json.make_scanner(Context()), K('NaN'), 0),
    err(_json.make_scanner, BadEncoding()),
    err(_json.make_scanner, Missing()),
    err(_json.make_scanner),
    err(_json.make_scanner, Context(), 1),
)

deep = err(json.loads, K('[' * 3000))
deep_unicode = err(json.loads, K(u'{"a":' * 3000))
deep_encode = err(json.dumps, reduce(lambda inner, _: [inner], range(3000), []))

RESULT = (str_errors, unicode_errors, scanner_errors, scanstring_errors, hooks_raise, deep, deep_unicode, deep_encode)
