import re

def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

def info(m):
    if m is None:
        return None
    return (m.group(), m.groups(), m.span(), m.lastindex, m.lastgroup, m.regs, m.pos, m.endpos, m.string)

p = re.compile(r'(?P<word>\w+)\s+(?P<num>\d+)?')
m = p.search('  hello 42 world')
n = re.match(r'(a)|(b)', 'b')
RESULT = [
    info(m), m.group('word', 2, 0), m.groupdict(), m.groupdict('-'), m.start('num'), m.end(1), m.span(2), m.re is p,
    info(p.match('x y')), info(p.match('  x', 2)), info(p.search('abc 1', 1, 4)), info(p.search('abc', 10)),
    info(n), n.groups('?'), n.span(1), n.start(1), n.group(1),
    err(m.group, 3), err(m.group, 'nope'), err(m.start, -1), err(m.span, 'x'), err(m.group, 1.5),
    info(re.match(r'a.*b', 'axxbyyb')), info(re.match(r'a.*?b', 'axxbyyb')), info(re.match(r'(a+)(a*)b', 'aaab')),
    info(re.match(r'(a+?)(a*)b', 'aaab')), info(re.match(r'(?:(a)|b)*', 'abab')), info(re.match(r'((a)|(b))+', 'abba')),
    info(re.match(r'(a{2,3}){2}', 'aaaaaa')), info(re.match(r'(a{2,3}?){2}', 'aaaaaa')), info(re.match(r'(ab|a)(bc|c)?$', 'abc')),
    info(re.match(r'(x*)*y', 'xxy')), info(re.match(r'(?:x?)*?y', 'xxy')), info(re.match(r'(a*)+$', 'aa')), info(re.match(r'(a|b)*?c', 'abac')),
    info(re.search(r'(\w)\1', 'abccd')), info(re.search(r'(?P<q>[\'"]).*?(?P=q)', 'say "hi" now')), info(re.search(r'(a)?(?(1)b|c)', 'xc')),
    info(re.search(r'(a)?(?(1)b|c)', 'ab')), info(re.search(r'foo(?=bar)', 'foobaz foobar')), info(re.search(r'foo(?!bar)', 'foobar foobaz')),
    info(re.search(r'(?<=a)b', 'cb ab')), info(re.search(r'(?<!a)b', 'ab cb')), info(re.search(r'\bis\b', 'this is')), info(re.search(r'\Bis\b', 'this is')),
    info(re.search(r'^$', '')), info(re.search(r'x*', 'aaa')), info(re.search(r'$', 'abc\n')), info(re.search(r'\Z', 'abc\n')), info(re.match(r'\A', 'q')),
    info(re.search(r'a|b|c', 'zzc')), info(re.search(r'[^a-c]+', 'abcdefa')), info(re.search(r'[\d\s]+', 'ab 12 c')), info(re.search(r'.+', 'ab\ncd')),
    info(re.match(r'(a)(b)?', 'a')), info(re.match(r'((a)(b))', 'ab')), info(re.search(r'(?:a(b)?)+', 'aba')),
    info(re.match(r'(a)(?:(b)|c)*', 'abcb')), info(re.match('a{3,}', 'aaaa')), info(re.match('a{,2}', 'aaaa')), info(re.match(r'(?:ab){2}', 'ababab')),
    info(re.match(r'\x41\101\n', 'AA\n')), info(re.search('needle', 'haystack with needle in it')), info(re.search('abcabd', 'abcabcabd')),
    info(re.match(r'(?s).', '\n')), info(re.match(r'.', '\n')), info(re.match(r'(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)\11', 'abcdefghijkk')),
    re.match('x', 'x').group(0), bool(re.match('', '')), info(re.compile('b').match('ab', 1)), info(re.compile('^b').search('ab', 1)),
    info(re.compile('a$').search('ab', 0, 1)), info(re.compile(r'\d+').search('a123', -5, 100)),
]
