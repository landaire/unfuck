# The _json module surface: types, members, and docstrings.
import json.decoder
import _json


def err(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except Exception as error:
        return (type(error).__name__, str(error))


class Context(object):
    encoding = u'latin-1'
    strict = 0
    object_hook = 'hook'
    object_pairs_hook = None
    parse_float = float
    parse_int = int
    parse_constant = 'constant'


scanner = _json.make_scanner(Context())
default_scanner = _json.make_scanner(json.decoder.JSONDecoder())
markers = {}
encoder = _json.make_encoder(markers, len, repr, 2, ':', ',', 'sort', 0, [])

scanner_members = ['encoding', 'strict', 'object_hook', 'object_pairs_hook', 'parse_float', 'parse_int', 'parse_constant']
encoder_members = ['markers', 'default', 'encoder', 'indent', 'key_separator', 'item_separator', 'sort_keys', 'skipkeys']


def subclass(base):
    class Derived(base):
        pass
    return Derived


def assign(target, name):
    setattr(target, name, 1)


def construction():
    fresh_scanner = _json.make_scanner.__new__(_json.make_scanner)
    fresh_encoder = _json.make_encoder.__new__(_json.make_encoder)
    states = [
        sorted(_json.make_scanner.__dict__), sorted(_json.make_encoder.__dict__),
        repr(_json.make_scanner.__dict__['__init__']), repr(_json.make_encoder.__dict__['__init__']),
        type(fresh_scanner).__name__, type(fresh_encoder).__name__,
        [getattr(fresh_scanner, name) for name in scanner_members],
        [getattr(fresh_encoder, name) for name in encoder_members],
        err(fresh_scanner.__init__, 1),
        err(fresh_scanner.__init__, json.decoder.JSONDecoder()),
        fresh_scanner(u'[1]', 0),
        err(fresh_encoder.__init__, None, None, None, None, ':', ',', 0, 0, 1),
        fresh_encoder([1], 0),
    ]
    return states


RESULT = (
    _json.make_scanner.__name__, _json.make_scanner.__module__, repr(_json.make_scanner),
    _json.make_encoder.__name__, _json.make_encoder.__module__, repr(_json.make_encoder),
    type(scanner) is _json.make_scanner, type(encoder) is _json.make_encoder,
    [getattr(scanner, name) for name in scanner_members],
    [(name, repr(getattr(_json.make_scanner, name))) for name in scanner_members],
    default_scanner.encoding, default_scanner.strict, default_scanner.parse_int is int,
    [getattr(encoder, name) for name in encoder_members],
    encoder.markers is markers, encoder.default is len,
    [(name, repr(getattr(_json.make_encoder, name))) for name in encoder_members],
    err(assign, scanner, 'strict'),
    err(assign, encoder, 'indent'),
    err(assign, scanner, 'other'),
    err(subclass, _json.make_scanner),
    err(subclass, _json.make_encoder),
    err(_json.make_scanner.__dict__['encoding'].__get__, encoder),
    sorted(name for name in dir(_json) if not name.startswith('__')),
    scanner(u'"x\ty"', 0),
    err(scanner, u'{}', 0),
    construction(),
)
