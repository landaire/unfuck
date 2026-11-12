import _sre
import sre_compile
import sre_parse

def err(f, *a):
    try:
        return f(*a)
    except Exception as e:
        return (type(e).__name__, str(e))

def code_of(pattern, flags=0):
    parsed = sre_parse.parse(pattern, flags)
    return sre_compile._code(parsed, flags), parsed.pattern.groups

def roundtrip(pattern, subject, flags=0):
    code, groups = code_of(pattern, flags)
    compiled = _sre.compile(pattern, flags, code, groups - 1, {}, [None] * groups)
    m = compiled.search(subject)
    return m and (m.span(), m.regs)

one, one_groups = code_of('(a)')
RESULT = [
    roundtrip(r'(a|bc)+d', 'xbcad'), roundtrip(r'(?<=x)(?=y)', 'xy'), roundtrip(r'(a)?(?(1)b|c)', 'c'), roundtrip(r'[^\d\s]{2,}?', '1 ab'),
    roundtrip(r'(?i)[k-m]+', 'KLm'), roundtrip(r'\bfoo\b', 'a foo b'), roundtrip(r'a(?#c)*', 'aaa'),
    err(_sre.compile, None, 0, [21, 0xffffffff, 1], 0), err(_sre.compile, None, 0, [], 0), err(_sre.compile, None, 0, [19], 0),
    err(_sre.compile, None, 0, [1], -1), err(_sre.compile, None, 0, [1], 101), err(_sre.compile, None, 0, [1], 2 ** 70),
    err(_sre.compile, None, 0, [12, 5, 1], 3), err(_sre.compile, None, 0, [6, 12, 1], 0),
    _sre.compile(None, 0, [1], 0).match('x').span(),
    _sre.compile('(a)', 0, one, 1, {}, {1: 'g'}).match('a').lastgroup, _sre.compile('(a)', 0, one, 1, {}, (None, 'g')).match('a').lastgroup,
]
