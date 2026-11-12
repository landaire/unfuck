import re

def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

def upper(m):
    return m.group().upper()

def drop(m):
    return None

def spans(iterator):
    return [(m.group(), m.span()) for m in iterator]

scanner = re.compile(r'\d').scanner('a1b22')
anchored = re.compile(r'\d').scanner('12a3')
RESULT = [
    re.sub(r'(\w+) (\w+)', r'\2 \1', 'hello world, good day'), re.sub(r'(?P<a>a)', r'<\g<a>\g<1>\g<0>>', 'banana'),
    re.sub(r'a', '-', 'banana', 2), re.subn(r'a', '-', 'banana'), re.subn(r'x', '-', 'banana'), re.sub(r'\w+', upper, 'ab cd'),
    re.sub(r'b', drop, 'abcb'), re.sub(r'x*', '-', 'abc'), re.subn(r'x*', '-', ''), re.sub(r'', '-', 'ab'), err(re.sub, r'(a)|b', r'[\1]', 'ab'),
    re.sub('a', r'\n\t\\', 'xa'), re.sub(u'a', u'\xe9', 'banana'), re.sub('(?m)^', '> ', 'a\nb'), re.sub('a', 'b', u'aa'),
    re.compile('a').sub('b', 'aaa', count=1), re.sub(r'\d', lambda m: str(int(m.group()) * 2), 'a1b5'),
    err(re.sub, '(a)', r'\2', 'a'), err(re.sub, 'a', r'\g<x>', 'a'), err(re.sub, 'a', '\\', 'a'), err(re.sub, 'a', 1, 'a'),
    re.split(r'\s+', 'a b  c'), re.split(r'(\s+)', 'a b  c'), re.split(r'(a)|(b)', 'xaybz'), re.split(r',', 'a,b,c', 1),
    re.split(r'x*', 'abc'), re.split(r'\b', 'ab cd'), re.split(r',', ''), re.split(r'(,)', ',a,'), re.split('$', 'ab'),
    re.findall(r'\d', 'a1b22'), re.findall(r'(\d)(\w)', 'a1b2c3'), re.findall(r'(\d)', 'a1b2'), re.findall(r'x*', 'ab'),
    re.findall(r'(a)|b', 'ab'), re.findall(r'\d+', 'a1b22c333', ), re.compile(r'\d').findall('1234', 1, 3),
    spans(re.finditer(r'\d+', 'a12b3')), spans(re.finditer(r'x*', 'ab')), spans(re.compile('a').finditer('aaa', 1)),
    scanner.search().group(), scanner.search().span(), scanner.search().span(), scanner.search(), scanner.search(),
    anchored.match().span(), anchored.match().span(), anchored.match(), anchored.search(), anchored.pattern.pattern,
    re.compile('a').scanner('aab').match().span(), re.match(r'(\w)(\w)', 'ab').expand(r'\2-\1-\g<0>'),
    re.sub('b', 'x', bytearray('abc')), re.findall('b', bytearray('abcb')), re.match('a', bytearray('a')).group(),
    re.split('b', bytearray('abc')), re.escape('a.b*c'), re.search('a', buffer('xa')) if False else None,
    err(re.match, 'a', 1), err(re.match, 'a', None), err(re.compile('a').match), err(re.compile('a').match, 'a', 0, 1, 2),
    err(re.compile('a').match, 'a', pattern='a'), re.compile('a').match(pattern='a').group(), err(re.compile('a').__copy__),
    err(re.match('a', 'a').__copy__), err(re.match('a', 'a').__deepcopy__, {}), err(re.compile('a').scanner),
    re.compile(r'(?P<x>a)(b)').groupindex, re.compile('a', re.I).flags, re.compile('(a)(b)').groups, re.compile('ab').pattern,
    re.template('a').match('a').group(), re.purge(),
]
