import _csv
import csv

def K(x):
    return x

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))

def show(d):
    return (d.delimiter, d.quotechar, d.escapechar, d.doublequote, d.skipinitialspace,
            d.lineterminator, d.quoting, getattr(d, 'strict', 'absent'))

def make(*a, **k):
    return err(lambda: show(_csv.Dialect(*a, **k)))

class Sub(_csv.Dialect):
    pass

class Partial:
    delimiter = ':'

class Attrs(object):
    @property
    def delimiter(self):
        raise ValueError('boom')
    quotechar = "'"

d0 = _csv.Dialect()

_csv.register_dialect('semi', delimiter=';', quoting=_csv.QUOTE_ALL)
_csv.register_dialect(u'uni', csv.excel_tab)
reg = sorted(_csv.list_dialects())
semi = show(_csv.get_dialect('semi'))
same = _csv.Dialect(_csv.get_dialect('semi')) is _csv.get_dialect('semi')
unreg = (err(_csv.unregister_dialect, 'semi'), err(_csv.unregister_dialect, 'semi'),
         err(_csv.unregister_dialect, []), err(_csv.get_dialect, 'semi'), err(_csv.get_dialect, []))

sniffer = csv.Sniffer()
sniffed = sniffer.sniff(K('a;b;c\r\n1;2;3\r\n4;5;6\r\n'))
sniffed2 = sniffer.sniff(K('"x","y"\n"1","2"\n'))

RESULT = (
    show(d0), make(K(';')) if False else make(delimiter=K(';')),
    make(quotechar=None), make(quotechar=None, quoting=_csv.QUOTE_MINIMAL),
    make(quoting=_csv.QUOTE_NONE, quotechar=None),
    make(delimiter=''), make(delimiter='ab'), make(delimiter=1), make(delimiter=None), make(delimiter='\x00'),
    make(quoting=7), make(quoting='1'), make(quoting=True), make(quoting=1L),
    make(lineterminator=None), make(lineterminator=5), make(lineterminator=u'\n'),
    make(escapechar=''), make(escapechar='\\'), make(escapechar=u'x'),
    make(doublequote=0, skipinitialspace=[1], strict='y'),
    make(Partial), make(Partial()), make(Attrs()), make('excel'), make('missing'), make(csv.excel()),
    make(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), make(bogus=1), make(Partial, delimiter=','),
    show(Sub(delimiter='-')), type(Sub(delimiter='-')).__name__, isinstance(Sub(), _csv.Dialect),
    type(_csv.Dialect(Sub())).__name__,
    err(_csv.Dialect.__new__, int), err(_csv.Dialect.__new__, 1), err(_csv.Dialect.__new__),
    type(_csv.Dialect.__new__(Sub, delimiter='+')).__name__,
    err(setattr, d0, 'delimiter', ';'), err(setattr, d0, 'quoting', 1), err(setattr, d0, 'x', 1),
    repr(_csv.Dialect.__dict__['delimiter']), repr(_csv.Dialect.__dict__['quoting']),
    _csv.Dialect.__module__, _csv.Dialect.__name__,
    reg, semi, same, unreg,
    err(_csv.register_dialect, 1), err(_csv.register_dialect), err(_csv.register_dialect, 'x', 'y', 'z'),
    err(_csv.register_dialect, 'bad', delimiter=5),
    err(_csv.list_dialects, 1),
    err(csv.register_dialect, 'bad2', quoting=9),
    err(lambda: csv.Dialect()),
    (_csv.QUOTE_MINIMAL, _csv.QUOTE_ALL, _csv.QUOTE_NONNUMERIC, _csv.QUOTE_NONE),
    _csv.__version__, csv.__version__, _csv.Error.__module__, _csv.Error.__mro__[1].__name__,
    csv.Error is _csv.Error,
    show(sniffed), sniffer.has_header(K('name,age\nbob,30\nal,4\n')), show(sniffed2) if hasattr(sniffed2, 'delimiter') and False else (sniffed2.delimiter, sniffed2.quotechar, sniffed2.doublequote),
    err(lambda: sniffer.sniff('abc').delimiter),
)
