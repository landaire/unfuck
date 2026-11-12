# Random samples of the % operator, format(), and str.format, drawn from a
# fixed pseudo-random sequence so that CPython and the interpreter see the
# same samples. OUTCOMES holds one line per sample: the repr of the result,
# or the exception type and arguments.
#
# Regenerate the expected outcomes with generate_format_samples.py.

SAMPLES_PER_KIND = 8000

_state = [20261111]


def rand(n):
    # The product overflows a 32-bit C long; int() keeps the state an int.
    _state[0] = int((_state[0] * 1103515245 + 12345) & 0x7fffffff)
    return (_state[0] >> 8) % n


def pick(items):
    return items[rand(len(items))]


def chance(percent):
    return rand(100) < percent


INTS = [0, 1, -1, 7, -42, 255, 65, 1000000, 2 ** 31 - 1, -2 ** 31, 2 ** 31, 2 ** 40, -2 ** 63,
        2 ** 64, 10 ** 25, -10 ** 25, True, False, 0L, 5L, -5L, 123456789, 0x10000, 0xffff]
FLOATS = [0.0, -0.0, 1.5, -2.5, 0.1, 1e-5, 1e-300, 5e-324, 1e16, 1.2345e15, 123456.789, -9.995,
          1e100, 1.7976931348623157e308, float('inf'), float('-inf'), float('nan'), 2.5, 0.5,
          99.99, 1234567.891, 1e10, 1e11, 0.001, 55.0, 3.14159265358979, -1e-7, 12345678901.0]
COMPLEXES = [1 + 2j, -1.5 - 0.5j, 1j, -1j, complex(-0.0, 0.0), 0j, complex(1e20, 1e-20),
             complex(float('inf'), float('nan')), 12345 + 67890j, complex(0.0, -2.5)]
STRS = ['', 'a', 'abc', 'hello world', '\xff', 'x%sy', '{0}', 'A' * 12]
UNICODES = [u'', u'a', u'\xe9t\xe9', u'\u1234', u'abc', u'\xff\x00z']


class Text(object):
    """Converts to text through user methods, one returning unicode."""

    def __str__(self):
        return u'\xe9!'

    def __repr__(self):
        return 'Text()'


class Number(object):
    def __int__(self):
        return 6

    def __float__(self):
        return 1.25

    def __repr__(self):
        return 'Number()'


class LongOnly(object):
    def __long__(self):
        return 3L

    def __repr__(self):
        return 'LongOnly()'


class Classic:
    def __int__(self):
        return 9

    def __float__(self):
        return 2.25

    def __str__(self):
        return 'classic'

    def __repr__(self):
        return 'Classic()'


class ClassicTrunc:
    def __trunc__(self):
        return 4

    def __repr__(self):
        return 'ClassicTrunc()'


class ClassicLong:
    def __long__(self):
        return 3L

    def __repr__(self):
        return 'ClassicLong()'


class IntSub(int):
    def __str__(self):
        return 'int!'


class FloatSub(float):
    def __int__(self):
        return 11

    def __str__(self):
        return 'float!'


class StrSub(str):
    def __str__(self):
        return 'str!'


class Formatted(object):
    def __format__(self, spec):
        if spec == 'bad':
            return 5
        return '<' + spec + '>'

    def __repr__(self):
        return 'Formatted()'


class Lookup(object):
    def __getitem__(self, key):
        return key * 2

    def __repr__(self):
        return 'Lookup()'


OTHERS = [None, [1, 2], (1,), (), {'a': 1}, Ellipsis, Text(), Number(), LongOnly(), Classic(),
          ClassicTrunc(), ClassicLong(), IntSub(42), FloatSub(-3.75), StrSub('sub'), Formatted(),
          Lookup(), u'\xe9'.encode('utf-8')]

NUMBERS = INTS + FLOATS
ANY = INTS + FLOATS + COMPLEXES + STRS + UNICODES + OTHERS


def outcome(function):
    try:
        return repr(function())
    except Exception as error:
        return '%s: %r' % (type(error).__name__, error.args)


def percent_spec(keys):
    text = '%'
    stars = []
    key = None
    if keys is not None:
        key = pick(keys)
        text += '(' + key + ')'
    for _ in range(rand(4)):
        text += pick('-+ #0')
    roll = rand(10)
    if roll < 4:
        text += str(rand(25))
    elif roll < 5:
        text += '*'
        stars.append(rand(61) - 30)
    roll = rand(20)
    if roll < 8:
        text += '.' + str(rand(20))
    elif roll < 9:
        text += '.*'
        stars.append(rand(36) - 5)
    elif roll < 10:
        text += '.'
    elif roll < 11:
        text += '.' + pick(['116', '117', '120'])
    if chance(5):
        text += pick('hlL')
    if chance(94):
        conversion = pick('diouxXeEfFgGcrs%')
    else:
        conversion = pick(['a', 'z', 'q', '\x01', '\xe9', ''])
    text += conversion
    return text, stars, conversion, key


def percent_value(conversion):
    if conversion in 'diouxX' and chance(70):
        return pick(INTS + FLOATS[:6])
    if conversion in 'eEfFgG' and chance(70):
        return pick(NUMBERS)
    if conversion == 'c' and chance(70):
        return pick([65, 0, 255, 256, -1, 0xffff, 0x10000, 2.5, 'x', 'xy', u'\xe9', '\xe9', u'', True, 2 ** 40])
    return pick(ANY)


def percent_sample():
    use_keys = chance(10)
    keys = ['a', 'b', 'k(1)'] if use_keys else None
    unicode_format = chance(25)
    pieces = []
    arguments = []
    mapping = {}
    for _ in range(1 + rand(3)):
        pieces.append(pick(['', '', 'x', ' ', 'ab', '%%', '-']))
        spec, stars, conversion, key = percent_spec(keys)
        pieces.append(spec)
        arguments.extend(stars)
        if conversion != '%':
            value = percent_value(conversion)
            if use_keys:
                mapping[key] = value
            else:
                arguments.append(value)
    if chance(5):
        pieces.append(pick(['\xff', 'z', '%', '%(']))
    fmt = ''.join(pieces)
    if unicode_format:
        fmt = fmt.decode('latin-1')
    if use_keys:
        args = mapping if not chance(10) else tuple(arguments)
    else:
        if chance(5) and arguments:
            arguments.pop()
        elif chance(5):
            arguments.append(pick(ANY))
        if len(arguments) == 1 and chance(40) and not isinstance(arguments[0], tuple):
            args = arguments[0]
        else:
            args = tuple(arguments)
    return (fmt, args), lambda: fmt % args


def spec_text(kinds):
    # Options a kind rejects appear rarely, so most samples format.
    textual = kinds is STRING_KINDS
    integral = kinds is INTEGER_KINDS
    text = ''
    roll = rand(10)
    if roll < 2:
        text += pick(' *0x<{') + pick('<>=^')
    elif roll < 4:
        text += pick('<>=^')
    if chance(4 if textual else 30):
        text += pick('+- ')
    if chance(4 if not integral else 20):
        text += '#'
    if chance(4 if textual else 15):
        text += '0'
    if chance(40):
        text += str(rand(20))
    if chance(4 if textual else 15):
        text += ','
    roll = rand(100)
    if roll < (8 if integral else 30):
        text += '.' + str(rand(15))
    elif roll < (10 if integral else 33):
        text += '.'
    if chance(80):
        text += pick(kinds)
    if chance(3):
        text += pick(['z', 'dd', '\xff', ',', '.2'])
    return text


SPEC_KINDS = list('bcdeEfFgGnosxX%') + ['', '', '']
INTEGER_KINDS = list('bcdnoxXeEfFgG%') + ['', '', '', '']
FLOAT_KINDS = list('eEfFgGn%') + ['', '', '']
COMPLEX_KINDS = list('eEfFgGn') + ['', '', '']
STRING_KINDS = ['s', '', '', '']


def format_sample():
    roll = rand(10)
    if roll < 3:
        value = pick(INTS + [True, 12345678, -1234567])
        kinds = INTEGER_KINDS
    elif roll < 6:
        value = pick(FLOATS + [-1234567.25, 1234.5])
        kinds = FLOAT_KINDS
    elif roll < 8:
        value = pick(COMPLEXES)
        kinds = COMPLEX_KINDS
    else:
        value = pick(STRS + UNICODES)
        kinds = STRING_KINDS
    if chance(10):
        kinds = SPEC_KINDS
    if chance(8):
        value = pick(OTHERS)
    spec = spec_text(kinds)
    if chance(15):
        spec = spec.decode('latin-1')
    return (value, spec), lambda: format(value, spec)


class Point(object):
    x = 3
    y = -1.5

    def __repr__(self):
        return 'Point()'


def field_name(numbering):
    if numbering == 'auto':
        name = ''
    elif numbering == 'manual':
        name = str(rand(4))
    else:
        name = pick(['a', 'b', 'p', 'a', 'b', 'p', 'a', 'b', 'p', 'missing'])
    if chance(10):
        name = pick(['', '0', 'a', 'p'])
    if chance(12):
        name += pick(['.x', '.y', '[0]', '[a]', '[-1]', '.', '[', '[0]x', '.real'])
    return name


def field_text(numbering):
    text = '{' + field_name(numbering)
    if chance(15):
        text += '!' + pick('rrrsssx')
    if chance(60):
        text += ':'
        if chance(10):
            # Only the keyword `w` holds a short spec; a positional
            # argument could name a huge width.
            text += '{w}'
        else:
            text += spec_text(SPEC_KINDS if chance(30) else STRING_KINDS + list('dfg'))
    if chance(98):
        text += '}'
    return text


def template_sample():
    numbering = pick(['auto', 'manual', 'keyword'])
    pieces = []
    for _ in range(1 + rand(3)):
        pieces.append(pick(['', '', 'x', '{{', '}}', ' = ', 'a{{b}}c']))
        pieces.append(field_text(numbering))
    if chance(3):
        pieces.append(pick(['{', '}', '{0', '{!}', '{:{:{}}}']))
    template = ''.join(pieces)
    if chance(20):
        template = template.decode('latin-1')
    count = 4 if chance(90) else rand(4)
    positional = tuple(pick(ANY + [Point(), [7, 8], {'a': 'item'}]) for _ in range(count))
    keywords = {}
    if chance(90):
        keywords['a'] = pick(ANY)
    if chance(90):
        keywords['b'] = pick(NUMBERS)
    if chance(80):
        keywords['p'] = Point()
    if chance(80):
        keywords['w'] = pick(['5', '>8', '+.3', 'x^9', '', 'z'])
    return (template, positional, keywords), lambda: template.format(*positional, **keywords)


def run():
    lines = []
    for sample in (percent_sample, format_sample, template_sample):
        for _ in range(SAMPLES_PER_KIND):
            description, function = sample()
            lines.append((description, outcome(function)))
    return lines


SAMPLES = run()
OUTCOMES = '\n'.join(line for _, line in SAMPLES)
