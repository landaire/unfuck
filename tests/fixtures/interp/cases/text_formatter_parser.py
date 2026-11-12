import string

def K(value):
    return value

def drain(iterator):
    items = []
    for _ in range(8):
        try:
            items.append(next(iterator))
        except StopIteration:
            items.append('stop')
            break
        except Exception as e:
            items.append((type(e).__name__, str(e)))
    return items

def split(text):
    try:
        first, rest = text._formatter_field_name_split()
        return (first, type(rest).__name__, drain(rest))
    except Exception as e:
        return (type(e).__name__, str(e))

formats = [
    'a{0!r:>3}b{{c}}{}{:x}', u'{a.b[0]}', 'a}b{c}', 'x{', '{0!}', '{0!rx}', '{a{b}c}',
    'plain', '', '{:{}}', '{!s}', '{\x00}', 'tail{0', u'{x!r}',
]
fields = ['0.a[1][x]', '', 'name', u'0[a]', 'a[', 'a]b', 'a.', 'a[]', 'a.b.c[01]', '99999999999999999999999']

class Upper(string.Formatter):
    def convert_field(self, value, conversion):
        if conversion == 'u':
            return str(value).upper()
        return string.Formatter.convert_field(self, value, conversion)

RESULT = [
    [drain(K(text)._formatter_parser()) for text in formats],
    [split(K(field)) for field in fields],
    type(K('')._formatter_parser()).__name__,
    type(K(u'')._formatter_parser()) is type(K('')._formatter_parser()),
    iter(K('a')._formatter_parser()).next(),
    string.Formatter().format('{0}-{name}-{1[0]}-{x.real}', 'a', [2], name='n', x=K(3)),
    Upper().format('{0!u} {0!r}', 'abc'),
    string.Formatter().vformat('{0:>5}|{1}', ('a', 'b'), {}),
]
