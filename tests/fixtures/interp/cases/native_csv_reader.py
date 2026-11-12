import _csv
import csv

def K(x):
    return x

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))

def rows(lines, *a, **k):
    def go():
        r = _csv.reader(lines, *a, **k)
        out = []
        for row in r:
            out.append((row, r.line_num))
        return out
    return err(go)

RESULT = (
    rows(K(['a,b,c\r\n', '1,2,3\n', '\n', 'x'])),
    rows(K(['"a,b","c""d",e\n'])),
    rows(K(['"multi\n', 'line",z\n'])),
    rows(K(['"unterminated\n'])),
    rows(K(['"unterminated\n']), strict=True),
    rows(K(['"a"b,c\n'])),
    rows(K(['"a"b,c\n']), strict=1),
    rows(K(['a, b,  c\n']), skipinitialspace=True),
    rows(K(['a\\,b,c\\\n', 'd\n']), escapechar='\\'),
    rows(K(['"a\\"b",c\n']), escapechar='\\', doublequote=False),
    rows(K(['a;b;"c;d"\n']), delimiter=';'),
    rows(K(["'a,b',c\n"]), quotechar="'"),
    rows(K(['"a",b\n']), quoting=_csv.QUOTE_NONE),
    rows(K(['1,2.5,"x",\n']), quoting=_csv.QUOTE_NONNUMERIC),
    rows(K(['1,abc\n']), quoting=_csv.QUOTE_NONNUMERIC),
    err(lambda: _csv.reader(K(['a\x00b\n'])).next()),
    rows(K(['a\rb\n'])),
    rows(K([u'uni,code\n'])),
    err(lambda: _csv.reader(K([u'a\x00b\n'])).next()),
    rows(K([u'\xe9\n'])),
    rows(K([1])),
    rows(K(['a,b\r\n', '\r\n', 'c\r\n'])),
    rows(K(['"a""\n'])),
    rows(K(['ab'])),
    rows(K(['""'])),
    rows(K(['a\tb\n']), 'excel-tab'),
    rows(K(['a,b\n']), 'nope'),
    rows(K(['a,b\n']), csv.excel),
    rows(K(['a|b\n']), delimiter='|', quotechar=None),
    err(_csv.reader),
    err(_csv.reader, 1),
    err(_csv.reader, [], 'excel', 3),
    err(_csv.field_size_limit, 5),
    rows(K(['abcdef,ab\n'])),
    rows(K(['ab,"abcdef"\n'])),
    err(_csv.field_size_limit, 128 * 1024),
    err(_csv.field_size_limit, 'x'),
    err(_csv.field_size_limit, 1, 2),
    err(_csv.field_size_limit),
    [sorted(row.items()) for row in csv.DictReader(K(['h1,h2\n', '1,2\n', '3\n', '4,5,6\n']))],
    err(lambda: _csv.reader([]).next(1)),
    err(lambda: _csv.reader([]).line_num),
    err(lambda: setattr(_csv.reader([]), 'line_num', 3)),
    err(lambda: type(_csv.reader([]))()),
    type(_csv.reader([])).__name__, type(_csv.reader([])).__module__,
    _csv.reader([], delimiter=';').dialect.delimiter,
)
