import _csv
import csv
from cStringIO import StringIO

def K(x):
    return x

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))

class Num(object):
    def __int__(self):
        return 3
    def __str__(self):
        return 'num'

class Plain(object):
    def __str__(self):
        return 'pl"ain'

class Seq(object):
    def __len__(self):
        return 2
    def __getitem__(self, i):
        if i >= 2:
            raise IndexError
        return 'it%d' % i

def write(rowlist, *a, **k):
    def go():
        f = StringIO()
        w = _csv.writer(f, *a, **k)
        results = [w.writerow(r) for r in rowlist]
        return f.getvalue(), results
    return err(go)

class Collect(object):
    def __init__(self):
        self.parts = []
    def write(self, s):
        self.parts.append(s)
        return len(s)

c = Collect()
cw = _csv.writer(c, lineterminator='\n')
returned = cw.writerow(['x', 'y'])
cw.writerows([['1'], (2, 3.5), 'ab', iter([])] if False else [['1'], (2, 3.5), 'ab'])

RESULT = (
    write(K([['a', 'b,c', 'd"e', None, 1, 2.5, 1.0 / 3, 10 ** 20, True, u'u']])),
    write(K([[''], [], [None]])),
    write(K([['a\nb', 'c\rd']])),
    write(K([['a', 'b']]), quoting=_csv.QUOTE_ALL),
    write(K([['a', 1, 2.0, Num(), Plain(), None, True]]), quoting=_csv.QUOTE_NONNUMERIC),
    write(K([['a,b']]), quoting=_csv.QUOTE_NONE),
    write(K([['a,b', 'c"d', 'e\\f']]), quoting=_csv.QUOTE_NONE, escapechar='\\'),
    write(K([['']]), quoting=_csv.QUOTE_NONE),
    write(K([['c"d', 'e\\f']]), doublequote=False, escapechar='\\'),
    write(K([['c"d']]), doublequote=False),
    write(K([['a;b', 'c']]), delimiter=';', lineterminator='|'),
    write(K([['a|b', 'x!y']]), lineterminator='|!'),
    write(K([['a\x00b', 'c']])),
    write(K([['s', 'q'], Seq()])),
    write(K([1])),
    write(K([set([1])])),
    write(K([{'a': 1}])),
    write(K(['abc'])),
    write(K([[u'\xe9']])),
    write(K([['a']]), lineterminator=u'\r\n'),
    write(K([['a']]), lineterminator=u'\x00\n'),
    write(K([['a']]), lineterminator='!\x00\n'),
    write(K([['a!b', 'c\nd']]), lineterminator='!\x00\n'),
    write(K([['a']]), 'excel-tab'),
    write(K([['a']]), csv.excel_tab),
    err(_csv.writer, 1),
    err(_csv.writer, Collect, 'excel', 1),
    err(_csv.writer),
    c.parts, returned,
    err(cw.writerows, 1),
    err(cw.writerow),
    err(cw.writerow, 1, 2),
    cw.dialect.lineterminator,
    type(cw).__name__,
    err(lambda: type(cw)()),
)
