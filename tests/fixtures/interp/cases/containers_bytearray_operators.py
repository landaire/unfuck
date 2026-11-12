B = bytearray
K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

def iadd(other):
    b = B('a')
    b += other
    return b

def imul(other):
    b = B('a')
    b *= other
    return b

class Index(object):
    def __index__(self):
        return 2

RESULT = [
    B('ab') + 'cd', B('ab') + B('cd'), K('ab') + B('cd'), (K('x') + B('y')).__alloc__(), B('ab') * 3, 3 * B('ab'),
    B('ab') * -1, B('ab') * Index(), iadd('b'), iadd(B('c')), imul(2), imul(0),
    B('a') < B('b'), B('a') == B('a'), B('ab') > 'a', K('ab') == B('ab'), K('ab') < B('b'), B('a') != u'a', B('a') == u'a',
    B('a') < u'a', cmp(B('a'), 'b'), sorted([B('b'), B('a'), 'c']), B('a') == 1, B('a') != None,
    98 in B('abc'), 'bc' in B('abc'), B('b') in B('abc'), 'x' in B('abc'), '' in B('abc'), 0 in B('abc'),
    len(B('abc')), list(B('ab')), [x for x in B('\x00\xff')], list(reversed(B('ab'))), B('abc')[1], B('abc')[-1], B('abcd')[1:3],
    '%s|%r' % (B('ab'), B('ab')), u'%s' % B('ab'), str(B('ab')), unicode(B('ab')), int(B('12')), long(B('12')), float(B('1.5')),
    max(B('azb')), sum(B('\x01\x02')), tuple(B('ab')), set(B('aab')) == set([97, 98]), dict.fromkeys(B('a')),
    err(lambda: B('a') + 5), err(lambda: B('a') + u'x'), err(lambda: u'x' + B('a')), err(iadd, 5), err(iadd, u'x'),
    err(lambda: B('a') * 'b'), err(lambda: B('a') * B('b')), err(lambda: B('a') * 1.5), err(imul, 'x'),
    err(lambda: 5 + B('a')), err(lambda: 256 in B('a')), err(lambda: u'b' in B('abc')),
    err(lambda: 10 ** 20 in B('a')), err(lambda: 1.5 in B('a')), err(lambda: B('a') in 'abc'), err(hash, B('a')),
    err(lambda: {B('a'): 1}), err(int, B('12'), 16), err(int, B('1x')), err(float, B('x')), err(unicode, B('a'), 'latin-1'),
    err(lambda: ''.join([B('a')])), err(lambda: u''.join([B('a')])), err(lambda: u'abc'.find(B('b'))),
    err(lambda: u'abc'.startswith(B('a'))), err(len, B), err(B.append, 'a', 1),
]
