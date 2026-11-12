import _sre
import re

def info(m):
    if m is None:
        return None
    return (m.span(), m.regs[1:], m.lastindex, m.pos, m.endpos)

def raw(code, subject, groups=0, how='match', *bounds):
    try:
        pattern = _sre.compile('x', 0, code, groups, {}, [None] * (groups + 1))
        return info(getattr(pattern, how)(subject, *bounds))
    except Exception as e:
        return (type(e).__name__, str(e))

def valid(code, groups=0):
    try:
        _sre.compile('x', 0, code, groups)
        return True
    except RuntimeError:
        return False

def lastgroup(indexgroup):
    return _sre.compile('x', 0, [21, 0, 21, 1, 1], 1, {}, indexgroup).match('').lastgroup

class Names(dict):
    pass

class Lookup(object):
    def __getitem__(self, key):
        return 'looked up %r' % key

class Listed(dict):
    def keys(self):
        return ['y']

    def __getitem__(self, key):
        return 1

def scan(pattern, subject, how, count, *bounds):
    scanner = re.compile(pattern).scanner(subject, *bounds)
    return [info(getattr(scanner, how)()) for i in range(count)]

RESULT = [
    # Literal operands compare as 32-bit values; folded literals fold both
    # sides, folded sets only the subject character.
    raw([19, 0x161, 1], 'a'), raw([24, 0x161, 1], 'a'), raw([20, 65, 1], 'a'), raw([25, 65, 1], 'A'),
    raw([16, 4, 19, 65, 0, 1], 'a'), raw([16, 4, 19, 97, 0, 1], 'A'),
    # An INFO block after the start is skipped; at the start it bounds the
    # subject length, and its prefix and set steer a search.
    raw([2, 17, 4, 0, 3, 0, 1], 'abc'), raw([17, 4, 0, 3, 0, 2, 1], 'ab'), raw([17, 4, 0, 3, 0, 19, 98, 1], 'aab', 0, 'search'),
    raw([17, 4, 0, 2, 0, 15, 4, 19, 98, 0, 1], 'aab', 0, 'search'), raw([17, 7, 4, 0, 0, 19, 97, 0, 1], 'xbab', 0, 'search'),
    raw([17, 10, 3, 2, 2, 2, 1, 97, 98, 0, 0, 19, 97, 19, 120, 1], 'xxab', 0, 'search'),
    raw([17, 8, 3, 1, 1, 1, 1, 97, 0, 19, 98, 1], 'xab', 0, 'search'), raw([19, 97, 2, 1], 'xab', 0, 'search'),
    # Marks set inside a failed negative lookahead stay in force.
    info(re.match(r'(?!(a)c)a', 'ab')), info(re.match(r'(?:(a)b|(a)c)', 'ac')), info(re.match(r'(a)(?:(?=(a))ax|a)', 'aa')),
    # Zero-width iterations of lazy repeats stop at the first repeat of a
    # position.
    info(re.match(r'(?:()|a)*?b', 'aab')), info(re.match(r'(?:()|a){2,}?b', 'aab')), info(re.match(r'(a?)*', 'aa')),
    # A repeat entered with only the first mark set does not save it, so a
    # failed iteration can leave it moved.
    info(re.search(r'(b()*)+?\1', 'bx')), info(re.search(r'(bb()*)+?\1', 'cbbx')),
    # Matches may start past the end; an empty repeat cannot.
    info(re.compile('()').match('abc', 2, 1)), info(re.compile('x*').match('abc', 2, 1)), info(re.compile('').search('abc', 2, 1)),
    scan('', 'ab', 'match', 4), scan('', 'ab', 'match', 4, 1, 0), scan('(?!$)', 'ab', 'match', 4), scan(r'\d', '12a3', 'match', 4),
    scan('a', 'xxa', 'match', 2, 1), scan('x', 'abc', 'search', 2), scan(r'(?<=a)', 'ab', 'search', 2, 1),
    # Lookbehind sees before pos; word boundaries need a nonempty subject.
    info(re.compile('(?<=a)b').search('ab', 1)), info(re.compile(r'\bb').search('ab', 1)), info(re.compile(r'\B').search('a', 0, 0)),
    # A literal prefix may claim more characters than the subject holds.
    raw([17, 10, 3, 0, 10, 2, 100, 97, 98, 0, 0, 19, 120, 1], 'zzabx', 0, 'search'),
    # lastgroup indexes any indexgroup but an exact dict; groupdict lists
    # the keys groupindex.keys() returns.
    [lastgroup(names) for names in ({1: 'a'}, Names({1: 'a'}), Lookup(), 'ab', [None], 5)],
    _sre.compile('x', 0, [21, 0, 21, 1, 1], 1, Listed(x=1), None).match('').groupdict(),
    # The structural check of code lists.
    [valid(code) for code in ([], [1], [0], [1, 19, 97], [19, 97, 1], [6, 11, 1], [6, 12, 1], [30, 1], [18, 2, 1], [22, 1])],
    [valid([21, mark, 1], groups) for mark, groups in ((201, 0), (202, 0), (3, 1), (4, 1), (5, 2), (6, 2))],
    [valid([12, group, 1], groups) for group, groups in ((99, 0), (100, 0), (1, 2), (2, 2))],
    [valid(code) for code in ([7, 4, 2, 18, 1, 0, 1], [7, 4, 2, 18, 3, 0, 1], [7, 4, 2, 18, 2, 4, 2, 18, 2, 0, 1], [7, 4, 2, 18, 6, 4, 2, 18, 2, 0, 1])],
    [valid(code, 1) for code in ([13, 0, 2, 2, 1], [13, 0, 4, 2, 1], [13, 0, 5, 2, 18, 2, 2, 1], [13, 0, 5, 2, 18, 0, 2, 1], [13, 0, 1, 2, 1])],
    [valid(code) for code in ([17, 4, 4, 0, 0, 1], [17, 4, 4, 0, 1, 1], [17, 4, 2, 0, 0, 1], [17, 6, 3, 0, 0, 0, 0, 1], [17, 4, 8, 0, 0, 1])],
    [valid(code) for code in ([29, 6, 0, 1, 2, 2, 1, 1], [29, 5, 1, 0, 2, 1, 1], [28, 4, 0, 1, 2, 1, 1], [4, 4, 0x80000000, 2, 1, 1], [15, 4, 9, 18, 0, 1])],
    [valid(code, groups) for code, groups in (([1], -1), ([1], 100), ([1], 101))],
]
