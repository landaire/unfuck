# Random JSON text, well formed and mutated, decoded from str and unicode
# documents; random scanner and scanstring calls; and random values
# encoded with random options; compared with CPython. The C encoder keeps
# dict order even when asked to sort keys, and writes bool keys as str()
# does.
import json
import json.decoder
import _json


STATE = [20161105]


def rnd(n):
    STATE[0] = (STATE[0] * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
    return int((STATE[0] >> 33) % n)


def pick(items):
    return items[rnd(len(items))]


def run(action):
    try:
        return action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


STRING_PIECES = ['a', 'Z', ' ', '\\n', '\\"', '\\\\', '\\/', '\\t', '\\u00e9', '\\u20AC', '\\ud834\\udd1e', '\\ud800', '\\x', '\\u12', '\t', '\x01', '\xc3\xa9', '\xff', '"']


def random_string():
    return '"' + ''.join(pick(STRING_PIECES) for _ in range(rnd(4))) + pick(['"', '"', '"', ''])


def random_number():
    return pick(['0', '-0', '12', '-7', '3.25', '1e3', '-2.5E-2', '1.', '01', '-', '1e', '1.5e+', '2147483647', '.5', '-Infinity', 'NaN', 'Infinity', '1E400',
                 '2147483648', '-2147483649', '4294967296', '9223372036854775808'])


def random_value(depth):
    kind = rnd(9 if depth < 4 else 5)
    if kind == 0:
        return random_number()
    if kind == 1:
        return random_string()
    if kind == 2:
        return pick(['true', 'false', 'null', 'nul', 'tru', 'x', ''])
    if kind == 3:
        return random_number()
    if kind == 4:
        return pick(['[]', '{}', ' ', '[', '{'])
    space = pick(['', ' ', '\n', '\t '])
    if kind in (5, 6):
        items = [random_value(depth + 1) for _ in range(rnd(4))]
        return '[' + space + (pick([',', ', ', ' ,', ',,', ' ']).join(items)) + space + pick([']', ']', ']', '', ',]'])
    members = []
    for _ in range(rnd(4)):
        members.append(random_string() + pick([':', ': ', ' :', '', '::']) + random_value(depth + 1))
    return '{' + space + pick([',', ', ', ',,', ' ']).join(members) + space + pick(['}', '}', '}', '', ',}'])


def random_document():
    text = pick(['', ' ', '\n']) + random_value(0) + pick(['', ' ', '\n', ' x', ']'])
    if rnd(4) == 0 and text:
        cut = rnd(len(text))
        text = text[:cut] + pick(['', ',', '"', '\\', '{', ']', ':']) + text[cut + 1:]
    return text


def sorted_value(value):
    if isinstance(value, dict):
        return ('dict', sorted((key, sorted_value(item)) for key, item in value.items()))
    if isinstance(value, list):
        return [sorted_value(item) for item in value]
    return value


def decode(text):
    return sorted_value(json.loads(text))


decoded = []
for _ in range(400):
    text = random_document()
    decoded.append((text, run(lambda: decode(text)), run(lambda: decode(text.decode('latin-1')))))

hooked = []
decoder = json.decoder.JSONDecoder(object_pairs_hook=lambda pairs: ('pairs', pairs), parse_float=lambda text: ('float', text), parse_int=lambda text: ('int', text), parse_constant=lambda text: ('constant', text), strict=False)
for _ in range(150):
    text = random_document()
    index = rnd(len(text) + 2)
    hooked.append((text, index, run(lambda: decoder.scan_once(text, index)), run(lambda: decoder.scan_once(text.decode('latin-1'), index))))

strings = []
for _ in range(150):
    text = random_string() + pick(['', 'tail', ' "x"'])
    end = rnd(len(text) + 2) - 1
    encoding = pick([None, 'latin-1', 'utf-8', 'ascii'])
    strict = rnd(2)
    strings.append((text, end, encoding, strict, run(lambda: _json.scanstring(text, end, encoding, strict)), run(lambda: _json.scanstring(text.decode('latin-1'), end, encoding, strict))))


def random_python(depth):
    kind = rnd(10 if depth < 3 else 7)
    if kind == 0:
        return rnd(2001) - 1000
    if kind == 1:
        return (rnd(20001) - 10000) / 8.0
    if kind == 2:
        return pick([None, True, False, float('inf'), float('nan'), -0.0, 1e300])
    if kind == 3:
        return ''.join(pick(['a', '"', '\\', '\n', '\x00', '\x7f', '/', ' ']) for _ in range(rnd(4)))
    if kind == 4:
        return u''.join(pick([u'a', u'\xe9', u'\u20ac', u'\ud834', u'\U0001d11e', u'"']) for _ in range(rnd(4)))
    if kind == 5:
        return pick(['\xc3\xa9', '\xff', 2 ** 20, -(2 ** 70)])
    if kind == 6:
        return pick([(), [], {}, set([1])])
    if kind == 7:
        return [random_python(depth + 1) for _ in range(rnd(4))]
    if kind == 8:
        return tuple(random_python(depth + 1) for _ in range(rnd(3)))
    key = pick([u'k', 'k', 1, 2.5, None, True, (1,), float('inf')])
    return {key: random_python(depth + 1)}


encoded = []
for _ in range(400):
    value = random_python(0)
    options = {}
    if rnd(2):
        options['sort_keys'] = True
    if rnd(3) == 0:
        options['skipkeys'] = True
    if rnd(3) == 0:
        options['allow_nan'] = False
    if rnd(3) == 0:
        options['separators'] = pick([(',', ':'), (' , ', ' : '), (';', '=')])
    if rnd(4) == 0:
        options['ensure_ascii'] = False
    if rnd(4) == 0:
        options['check_circular'] = False
    if rnd(4) == 0:
        options['default'] = lambda value: sorted(value) if isinstance(value, set) else repr(value)
    encoded.append((sorted((key, repr(item)) for key, item in options.items() if key != 'default'), run(lambda: json.dumps(value, **options))))

escaped = []
for _ in range(100):
    text = random_python(3)
    escaped.append(run(lambda: _json.encode_basestring_ascii(text)))

sorting = _json.make_encoder(None, None, _json.encode_basestring_ascii, None, ':', ',', True, False, True)
plain = _json.make_encoder(None, None, _json.encode_basestring_ascii, None, ':', ',', False, False, True)
ordered = []
for _ in range(40):
    value = dict((rnd(40) - 5, rnd(10)) for _ in range(rnd(6)))
    if rnd(2):
        value[pick([True, False, 0.5, 2.5, 2 ** 31, -2 ** 31 - 1, 2 ** 40])] = 1
    for _ in range(rnd(4)):
        value[pick(['a', 'b', 'key', 'other', u'k', u'\xe9', 'ab', 'ba'])] = rnd(10)
    ordered.append((run(lambda: sorting(value, 0)), run(lambda: plain(value, 0))))

RESULT = (decoded, hooked, strings, encoded, escaped, ordered)
